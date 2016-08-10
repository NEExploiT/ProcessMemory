module ProcessMemory
  # ProcessMemoryExに幾つか追加
  class ProcessMemoryEx
    class << self
      def ptr(addr)
        latest.ptr addr
      end

      def ptr_buf(addr, size)
        latest.ptr_buf addr, size
      end

      def ptr_fmt(addr, size, fmt)
        latest.ptr_fmt addr, size, fmt
      end

      def MName(name) # rubocop:disable Style/MethodName
        latest.MName name
      end
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
