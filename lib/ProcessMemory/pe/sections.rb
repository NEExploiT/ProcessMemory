module PE
  # モジュールとセクションデータが関連づいてる奴
  class ModuleSectionData
    def initialize(section, ix, base)
      @section = section
      @index = ix
      @base = base
      @virtual_address = section.VirtualAddress
      @range = ((@virtual_address + base)..(section.VirtualSize + @virtual_address + base))
      @name = section.name_str
    end

    # 実アドレスがセクションに属しているか調べる
    # @param ra [Integer] target real address
    # @return [Bool] 属している場合はtrue 属していない場合はfalse
    def cover?(ra)
      @range.cover? ra
    end
    attr_reader :index, :range, :name, :virtual_address
  end

  # 各モジュールごとのセクションテーブル情報
  class ModuleSections
    ImageSectionHeader = PE::PEFormat::ImageSectionHeader
    ImageSectionHeaderSize = PEFormat::SizeOfImageSectionHeader
    def initialize(mem, base, offset, count)
      @mem = mem
      @base = base
      @offset = offset
      @count = count
      @sections = reads
    end

    # @param addr [Integer] target address
    # @return [ModuleSectionData] 指定アドレスがセクションに属している場合セクション情報を返す
    def find_section(addr)
      @sections.find{|it| it.cover? addr }
    end

    private

    def read(offset)
      ImageSectionHeader.new Fiddle::Pointer[@mem.ptr_buf(offset, ImageSectionHeaderSize)]
    end

    def reads
      Array.new(@count){|ix|
        current = @offset + ImageSectionHeaderSize * ix
        ModuleSectionData.new read(current), ix, @base
      }
    end
  end
end
