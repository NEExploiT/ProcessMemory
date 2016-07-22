require 'ProcessMemory/pe'

describe PE do
  let(:mem){ ProcessMemory::ProcessMemoryEx.new Process.pid }
  describe PE::PEModule do
    let(:pe){ PE::PEModule.new mem }
    describe '#ptr_i32' do
      it 'read int32' do
        expect(pe.ptr_i32(mem.base_addr)).to eq 0x00905A4D
      end
    end
    describe '#address_of' do
      it 'is nil when out of range' do
        expect(pe.address_of(0xffffffff)).to eq nil
      end
      it 'is PE::ModuleSectionData' do
        base = mem.base_addr
        # TODO: ここのマジックナンバーはあまり保証できず微妙
        expect(pe.address_of(base + 0x15000)).to be_a PE::ModuleSectionData
      end
    end
    describe '#base_name' do
      it '== ruby.exe' do
        expect(pe.base_name).to eq 'ruby.exe'
      end
    end
  end
end
