# coding: utf-8
require 'ProcessMemory/version'
require 'fiddle/import'
require 'fiddle/types'

module ProcessMemory
  # Windows API Wrapper
  module WinMemAPI
    extend Fiddle::Importer
    dlload 'kernel32', 'psapi'
    include Fiddle::BasicTypes
    include Fiddle::Win32Types

    extern 'HANDLE OpenProcess(DWORD, BOOL, DWORD)', :stdcall
    extern 'BOOL CloseHandle(HANDLE)', :stdcall
    extern 'BOOL ReadProcessMemory(HANDLE, PVOID, LPSTR, DWORD, PDWORD)', :stdcall
    extern 'BOOL WriteProcessMemory(HANDLE, PVOID, LPSTR, DWORD, PDWORD)', :stdcall

    extern 'BOOL EnumProcessModulesEx(HANDLE, LPSTR, DWORD, PDWORD, DWORD)', :stdcall
    extern 'DWORD GetModuleBaseNameW(HANDLE, HANDLE, LPSTR, DWORD)', :stdcall

    module OpenProcFlg
      PROC_READ = 0x10
      PROC_WRITE = 0x20
      PROC_Q_INFO = 0x0400
      PROC_RW   = PROC_READ | PROC_WRITE
      READ_INFO = PROC_READ | PROC_Q_INFO
      RW_INFO   = PROC_RW   | PROC_Q_INFO
    end
    SIZEOF_PTR = sizeof 'void*'

    module EnumFilterFlg
      LIST_MODULES_32BIT = 1
      LIST_MODULES_64BIT = 2
      LIST_MODULES_ALL   = 3
      LIST_MODULES_DEFAULT = 0
    end
  end

  # TODO: ファイナライザ
  # ProcessMemory External
  class ProcessMemoryEx
    I_am_x64 = WinMemAPI::SIZEOF_PTR == 8

    # コンストラクタ
    # @param [Integer] pid プロセスID
    def initialize(pid)
      @pid       = pid
      @h_process = WinMemAPI.OpenProcess(WinMemAPI::OpenProcFlg::READ_INFO, 0, pid)
      # オープン失敗
      raise ArgumentError, "process open failed. pid:#{@pid}" if @h_process == 0

      @target_is_x64 = detect_x64

      @@latest = self # rubocop:disable Style/ClassVars

      # 一応解放処理
      at_exit{
        WinMemAPI.CloseHandle(@h_process)
      }
    end

    # 指定サイズ読み込む
    # @param [Integer] addr 読み取り元アドレス
    # @param [Integer] size 読み込みサイズ
    # @return [String] 読み取ったデータ
    def ptr_buf(addr, size)
      buffer = "\0" * size
      lpsize = "\0\0\0\0\0\0\0\0".b
      WinMemAPI.ReadProcessMemory(@h_process, addr, buffer, size, lpsize)
      buffer
    end

    # データを読み込み、指定フォーマットでunpackした結果を返す
    # @param addr [Integer] 読み取り元アドレス
    # @param size [Integer] 読み込みサイズ
    # @param fmt  [String]  pack文字列
    # @return 指定アドレスを読み込んだ結果にunpackしたもの もしsizeが1以下の場合は最初の要素を返す
    def ptr_fmt(addr, size, fmt)
      ary = ptr_buf(addr, size).unpack(fmt)
      ary.size == 1 ? ary[0] : ary
    end

    # 指定アドレスから4byteもしくは8byte読み込みリトルエンディアンの整数とみなした結果を返す
    # @param addr [Integer] 読み取り元アドレス
    # @return [Integer] 読み取ったデータ
    def ptr(addr)
      @target_is_x64 ? ptr_fmt(addr, 8, 'VV').tap{|l, h| break h << 32 | l } : ptr_fmt(addr, 4, 'V')
    end

    # modules
    # アドレスをキー,モジュール名を値としたハッシュを返す
    # 重複を考えてモジュール名をキーとしない
    def modules
      @modules ||= modules_read.to_h
    end

    # detect_x64
    # target プロセスが64bitか否かを判別する
    # true => 64bit process
    # false => 32bit process
    def detect_x64
      lpcb_needed = "\0\0\0\0\0\0\0\0".b

      WinMemAPI.EnumProcessModulesEx(@h_process, 0, 0, lpcb_needed, WinMemAPI::EnumFilterFlg::LIST_MODULES_32BIT)
      (lpcb_needed.unpack('V')[0]) == 0
    end

    def modules_read
      len = 32 * WinMemAPI::SIZEOF_PTR
      initial_len = len
      lph_module = "\0" * len
      lpcb_needed = "\0\0\0\0\0\0\0\0".b
      # 対象プロセスが64bitの場合は変更する
      flg = @target_is_x64 ? WinMemAPI::EnumFilterFlg::LIST_MODULES_64BIT : WinMemAPI::EnumFilterFlg::LIST_MODULES_32BIT

      WinMemAPI.EnumProcessModulesEx(@h_process, lph_module, len, lpcb_needed, flg)
      if (len = lpcb_needed.unpack('V')[0]) > initial_len
        lph_module = "\0" * len
        WinMemAPI.EnumProcessModulesEx(@h_process, lph_module, len, lpcb_needed, flg)
      elsif len == 0
        # 失敗
        return nil
      end

      result = lph_module.unpack('V*')
      if I_am_x64
        # hostが64bitの場合 ポインタサイズが64bitなので一気に変換はできない
        result = result.each_slice(2).map{|l, h|
          h << 32 | l
        }
      end

      # exeのベースアドレスを取得
      @main_module_addr ||= result[0]

      # GetModuleBaseNameでベース名を取得する
      result.select{|it| it != 0 }.map{|it|
        namelen = 260
        namebuf = "\0".encode(Encoding::UTF_16LE) * namelen
        result_len = WinMemAPI.GetModuleBaseNameW(@h_process, it, namebuf, namelen)
        next [it, namebuf[0, result_len].encode(Encoding::UTF_8)] if result_len > 0
        # TODO: 失敗 260で足りない事はないと思うんだが一応
        [it, nil]
      }
    end

    # @param (option) name [String] モジュールの名前 nilの場合は実行ファイルのベースを取得
    # @return 指定モジュールのベースアドレス
    def base_addr(name = nil)
      if name.to_s.empty?
        modules if @main_module_addr.nil?
        @main_module_addr
      else
        MName name
      end
    end

    # SSGのMName::に対応
    # @param name [String] モジュールの名前 nilの場合は実行ファイルのベースを取得
    # @return 指定モジュールのベースアドレス
    def MName(name) # rubocop:disable Style/MethodName
      modules.select{|_, v| v == name }.sort[0][0]
    end

    def self.ptr(addr)
      @@latest.ptr addr
    end

    def self.ptr_buf(addr, size)
      @@latest.ptr_buf addr, size
    end

    def self.ptr_fmt(addr, size, fmt)
      @@latest.ptr_fmt addr, size, fmt
    end

    def self.MName(name) # rubocop:disable Style/MethodName
      @@latest.MName name
    end
  end # End of class ProcessMemoryEx

  # ユーティリティーモジュール
  # includeする事で、省略記法が使えるようになる
  module ProcessMemoryUtil
    module_function def ptr(addr)
      ProcessMemoryEx.ptr addr
    end

    module_function def MName(name) # rubocop:disable Style/MethodName
      ProcessMemoryEx.MName name
    end

    module_function def memoryutil_startup
      if ARGV.empty?
        puts '対象exeのpidを入力してください'
        s = gets.chop
      else
        s = ARGV[0]
      end

      ProcessMemoryEx.new s.to_i 0
    end
  end # End of Module ProcessMemoryUtil
end # End of Module ProcessMemory
