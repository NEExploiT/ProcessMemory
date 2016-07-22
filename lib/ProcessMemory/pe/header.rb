module PE
  # PE Headers
  module PEFormat
    extend Fiddle::Importer
    dlload # これがないと以下2行でエラーが出る
    # include Fiddle::BasicTypes
    include Fiddle::Win32Types
    ImageSectionHeader = struct %w[
      char[8]\ Name
      DWORD32\ VirtualSize
      DWORD32\ VirtualAddress
      DWORD32\ SizeOfRawData
      DWORD32\ PointerToRawData
      DWORD32\ PointerToRelocations
      DWORD32\ PointerToLinenumbers
      WORD\ NumberOfRelocations
      WORD\ NumberOfLinenumbers
      DWORD32\ Characteristics
    ]

    # 拡張してみる
    ImageSectionHeader.prepend Module.new{
      def name_str
        self.Name.pack('c8').unpack('Z*').first
      end
    }

    FileHeader = struct %w[
      WORD\ Machine
      WORD\ NumberOfSections
      DWORD32\ TimeDateStamp
      DWORD32\ PointerToSymbolTable
      DWORD32\ NumberOfSymbols
      WORD\ SizeOfOptionalHeader
      WORD\ Characteristics
    ]

    OptionalPrefix = %w[
      WORD\ Magic
      BYTE\ MajorLinkVersion
      BYTE\ MinerLinkVersion
      DWORD32\ SizeOfCode
      DWORD32\ SizeOfInitialData
      DWORD32\ SizeOfUnInitialData
      DWORD32\ AddressOfEntryPoint
      DWORD32\ BaseOfCode
    ].freeze

    OptionalSuffix = %w[
      DWORD32\ SectionAlignment
      DWORD32\ FileAlignment
      WORD\ MajorOperatingSystemVersion
      WORD\ MinorOperatingSystemVersion
      WORD\ MajorImageVersion
      WORD\ MinorImageVersion
      WORD\ MajorSubSystemVersion
      WORD\ MinorSubSystemVersion
      DWORD32\ Win32VersionValue
      DWORD32\ SizeOfImage
      DWORD32\ SizeOfHeaders
      DWORD32\ CheckSum
      WORD\ Subsystem
      WORD\ DllCharacteristics
      DWORD32\ SizeOfStackReserve
      DWORD32\ SizeOfStackCommit
      DWORD32\ SizeOfHeapReserve
      DWORD32\ SizeOfHeapCommit
      DWORD32\ LoaderFlags
      DWORD32\ NumberOfRvaAndSizes
    ].freeze

    OptionalHeaderx86 = struct OptionalPrefix + %w[
      DWORD32\ BaseOfData
      DWORD32\ ImageBase
    ] + OptionalSuffix

    OptionalHeaderx64 = struct OptionalPrefix + %w[
      DWORD64\ ImageBase
    ] + OptionalSuffix

    SizeOfImageSectionHeader = ImageSectionHeader.size
    SizeOfOptionalHeader = OptionalHeaderx86.size
    SizeOfFileHeader = FileHeader.size

    # IDEA: 再配置情報
    # IMAGE_BASE_RELOCATION = struct %w[
    #  DWORD32\ VirtualAddress
    #  DWORD32\ SizeOfBlock
    #  WORD\ TypeOffset
    # ]
  end # End of PELib::PEFormat
end
