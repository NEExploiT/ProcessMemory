require 'ProcessMemory'

require './lib/pe/header.rb'
require './lib/pe/sections.rb'
# Dir[File.dirname(__FILE__) + '/pe/*.rb'].each{|file| require file }

module PE
  # メモリ上のPEフォーマットを扱う
  class PEModule
    # コンストラクタ
    # @param mem [ProcessMemoryEx] 入力元
    # @param base [Integer] base address
    def initialize(mem, base = nil)
      @mem = mem
      @base_addr = base || mem.base_addr
      @base_name = mem.modules[@base_addr]

      # ヘッダ解析
      @nt_header = @base_addr + ptr_i32(@base_addr + 0x3C)
      @file_header = ptr_struct @nt_header + 4, PEFormat::FileHeader, PEFormat::SizeOfFileHeader
      optiheader = @nt_header + 4 + PEFormat::SizeOfFileHeader
      @optional_header = analyze_optiheader optiheader
      @data_directories = analyze_datadirs optiheader + PEFormat::SizeOfOptionalHeader

      @size = @optional_header.SizeOfImage

      # セクション解析
      sec_offset = optiheader + @file_header.SizeOfOptionalHeader
      @sections = PE::ModuleSections.new @mem, @base_addr, sec_offset,
                                         @file_header.NumberOfSections
    end

    attr_reader :base_name, :base_addr, :size

    def address_of(addr)
      @sections.find_section addr
    end

    # Get Int32 Value from addr
    # @param addr [Integer] target address
    # @return [Integer] read Value
    def ptr_i32(addr)
      @mem.ptr_fmt(addr, 4, 'V')
    end

    # 構造体を読み込む
    # @param addr [Integer]  読み取りアドレス
    # @param struct [Class]  構造体クラス
    # @return [Fiddle::CStruct] 読み取った構造体
    def ptr_struct(addr, struct, size = nil)
      struct.new Fiddle::Pointer[@mem.ptr_buf(addr, size || struct.size)]
    end

    private

    def analyze_optiheader(opti)
      case @mem.ptr_fmt(opti, 2, 'v')
      when 0x010B then ptr_struct(opti, PEFormat::OptionalHeaderx86, PEFormat::SizeOfOptionalHeader)
      when 0x020B then ptr_struct(opti, PEFormat::OptionalHeaderx64, PEFormat::SizeOfOptionalHeader)
      else
        raise "err: unknown optinalmagic (0x#{magic.to_s 16})"
      end
    end

    # @return [Hash] Analyzed DataDirectories
    def analyze_datadirs(offset)
      keys = %i[Export Import Resource Exception
                Certificate BaseRelocation DebugInfo Architecture
                GPtr TLS LoadCfg BoundImport
                IAT DelayImport CLRHeader _Reserve]
      @mem.ptr_fmt(offset, 8 * 16, 'V*').each_slice(2)
          .with_index.with_object({}) do |(data, ix), memo|
        memo[keys[ix]] = data
      end
    end
  end # End Of class PELib
end
