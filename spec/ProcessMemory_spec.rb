# coding: utf-8
require 'spec_helper'

describe ProcessMemory do
  it 'has a version number' do
    expect(ProcessMemory::VERSION).not_to be nil
  end

  let(:mem){
    ProcessMemory::ProcessMemoryEx.new $$
  }

  describe '#ptr_buf' do
    it 'read string' do
      TESTSTRING = "fake strings"
      test = Fiddle::Pointer[TESTSTRING]
      expect(
        mem.ptr_buf(test, test.size)
      ).to eq(TESTSTRING)
    end
  end

  TESTINT32 = 0xDEADBEEF
  TESTINT64 = 0xCAFEBABE15C001

  describe '#ptr' do
    host_is_x64 = ProcessMemory::WinMemAPI::SIZEOF_PTR == 8 && 'ruby.exe is x64 version'
    host_is_x86 = ProcessMemory::WinMemAPI::SIZEOF_PTR == 4 && 'ruby.exe is x86 version'

    it 'read int32' do
      testp = Fiddle::Pointer[[TESTINT32].pack('q')]
      expect(mem.ptr(testp)).to eq(TESTINT32)
    end

    context 'when host(ruby.exe) is x64', :skip => host_is_x86 do
      it 'read int64' do
        testp = Fiddle::Pointer[[TESTINT64].pack('q')]
        expect(mem.ptr(testp)).to eq(TESTINT64)
      end
    end
    context 'when host(ruby.exe) is x86', :skip => host_is_x64 do
      it 'does not read int64' do
        testp = Fiddle::Pointer[[TESTINT64].pack('q')]
        expect(mem.ptr(testp)).to_not eq(TESTINT64)
      end
    end
  end # End of describe '#ptr'

  describe '#ptr_fmt' do
    it 'read single int64' do
      testp = Fiddle::Pointer[[TESTINT64].pack('q')]
      expect(mem.ptr_fmt(testp, 8, 'q')).to eq(TESTINT64)
    end
    it 'read multi int64' do
      test_data = [0xcafebabe, 0xC001Babe]
      testp = Fiddle::Pointer[test_data.pack('qq')]
      expect(mem.ptr_fmt(testp, testp.size, 'qq')).to eq(test_data)
    end
  end # End of describe '#ptr_fmt'
end # describe ProcessMemory
