module ProcessMemory
  # ProcessMemoryExに幾つか追加
  class ProcessMemoryEx
    # inspect modulesを入れるとあまりに長いので隠す
    def inspect
      # #<ProcessMemory::ProcessMemoryEx:0x000000029dc158 @pid=13508, @h_process=160, @target_is_x64=true>x
      format("\#<#{self.class.name}:%0#{I_am_x64 ? 16 : 8}x @pid=#{@pid}, @h_process=#{@h_process}," \
      " @target_is_x64=#{@target_is_x64}>", __id__)
    end
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
