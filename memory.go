package memory

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32/user32"
	windows "golang.org/x/sys/windows"
)

type Memory struct {
	rpm        *syscall.Proc
	wpm        *syscall.Proc
	vap        *syscall.Proc
	ProcHandle windows.Handle
	BaseInfo   windows.ModuleEntry32
	Pid        uint32
}

type MemoryRegion struct {
	BaseAddress uintptr
	RegionSize  uintptr
}

type Pattern struct {
	Bytes      []byte
	Mask       string
	Offset     int
	Size       int
	Patch      bool
	PatchBytes []byte
}

type StaticPointer struct {
	BaseOffset int64
	Offsets    []int32
	LastOff    int32
	Uses       string
}

func (p *StaticPointer) GetAddress(mem *Memory) int64 {
	return mem.CalculateAddress(*p)
}

func NewMemoryRW(processName string) *Memory {
	return newMemory(processName, processName, true)
}

func NewMemoryMRW(processName string, moduleName string) *Memory {
	return newMemory(processName, moduleName, true)
}

func NewMemoryM(processName string, moduleName string) *Memory {
	return newMemory(processName, moduleName, false)
}

func NewMemory(processName string) *Memory {
	return newMemory(processName, processName, false)
}

func newMemory(processName string, moduleName string, write bool) *Memory {

	result, err := findProcessByName(processName)

	if err != nil || len(result) <= 0 {
		user32.MessageBox(0, fmt.Sprintf("Cannot find %s", processName), "Error", 0)
		syscall.Exit(0)
	}

	dll, _ := syscall.LoadDLL("kernel32.dll")

	var mem = Memory{}
	var access uint32

	if write {
		access = windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ | windows.PROCESS_VM_OPERATION
	} else {
		access = windows.PROCESS_VM_READ | windows.PROCESS_VM_OPERATION
	}

	handle, err := windows.OpenProcess(access, false, result[0])

	if err != nil {
		fmt.Println("Failed to open process")
		return nil
	}

	rpm, _ := dll.FindProc("ReadProcessMemory")
	wpm, _ := dll.FindProc("WriteProcessMemory")
	vap, _ := dll.FindProc("VirtualProtectEx")

	mem.ProcHandle = handle
	mem.rpm = rpm
	mem.wpm = wpm
	mem.vap = vap
	mem.Pid = result[0]
	module, err := getModule(moduleName, result[0])

	if err != nil {
		user32.MessageBox(0, "Error finding module", "Error", 0)
		syscall.Exit(0)
	}

	mem.BaseInfo = module
	return &mem
}

func (m *Memory) WriteDouble(addr int64, value float64) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, math.Float64bits(value))
	m.wpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(0))
}

func (m *Memory) WriteFloat(addr int64, value float32) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, math.Float32bits(value))
	m.wpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(0))
}

func (m *Memory) WriteInt(addr int64, value int32) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(value))
	m.wpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(0))
}

func (m *Memory) PatchAt(addr uintptr, bytes []byte) error {
	var oldProtect uintptr
	r, _, err := m.vap.Call(
		uintptr(m.ProcHandle),
		addr,
		uintptr(len(bytes)),
		uintptr(syscall.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if r == 0 {
		return err
	}

	r, _, err = m.wpm.Call(
		uintptr(m.ProcHandle),
		addr,
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		0)

	if r == 0 {
		return err
	}

	var temp uintptr
	r, _, err = m.vap.Call(
		uintptr(m.ProcHandle),
		addr,
		uintptr(len(bytes)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&temp)),
	)

	if r == 0 {
		return err
	}

	return nil
}

func ReadStruct[T any](addr int64, m *Memory, value *T) {
	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(value)),
		uintptr(binary.Size(value)),
		uintptr(0),
	)
}

func (m *Memory) ReadStruct(addr uintptr, value unsafe.Pointer, size int) {
	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(value),
		uintptr(size),
		uintptr(0),
	)
}

func (m *Memory) ReadInt(addr int64) int32 {
	var (
		data   [4]byte
		length uint32
	)

	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	bits := binary.LittleEndian.Uint32(data[:])
	return int32(bits)
}

func (m *Memory) ReadFloat(addr int64) float32 {
	var (
		data   [4]byte
		length uint32
	)

	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	bits := binary.LittleEndian.Uint32(data[:])
	float := math.Float32frombits(bits)
	return float
}

func (m *Memory) ReadDouble(addr int64) float64 {
	var (
		data   [8]byte
		length uint32
	)

	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	bits := binary.LittleEndian.Uint64(data[:])
	float := math.Float64frombits(bits)
	return float
}

func (m *Memory) Read(addr uintptr, buffer *[]byte, size int64) int64 {
	buff := *buffer
	var bytesReaded uint32
	m.rpm.Call(
		uintptr(m.ProcHandle),
		addr,
		uintptr(unsafe.Pointer(&buff[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesReaded)),
	)
	return int64(bytesReaded)
}

func (m *Memory) FindPattern(pattern Pattern) uintptr {

	buffer := make([]byte, m.BaseInfo.ModBaseSize)
	m.Read(m.BaseInfo.ModBaseAddr, &buffer, int64(m.BaseInfo.ModBaseSize))

	for i := 0; i <= len(buffer)-len(pattern.Bytes); i++ {
		found := true
		for j := 0; j < len(pattern.Bytes); j++ {
			if pattern.Mask[j] != '?' && pattern.Bytes[j] != buffer[i+j] {
				found = false
				break
			}
		}
		if found {
			addr := m.BaseInfo.ModBaseAddr + uintptr(i)
			buff := make([]byte, 4)
			m.Read(addr+uintptr(pattern.Offset), &buff, 4)
			addr += uintptr(pattern.Size) + uintptr(binary.LittleEndian.Uint32(buff[:]))
			buffer = nil
			return addr
		}
	}
	return 0
}

func (m *Memory) FindPatternEx(pattern Pattern) uintptr {
	buffer := make([]byte, m.BaseInfo.ModBaseSize)
	m.Read(m.BaseInfo.ModBaseAddr, &buffer, int64(m.BaseInfo.ModBaseSize))

	for i := 0; i <= len(buffer)-len(pattern.Bytes); i++ {
		found := true
		for j := 0; j < len(pattern.Bytes); j++ {
			if pattern.Mask[j] != '?' && pattern.Bytes[j] != buffer[i+j] {
				found = false
				break
			}
		}
		if found {
			addr := m.BaseInfo.ModBaseAddr + uintptr(i)
			buffer = nil
			return addr
		}
	}
	return 0
}

func findProcessByName(processName string) ([]uint32, error) {
	var processIDs [2048]uint32
	var cbNeeded uint32

	err := windows.EnumProcesses(processIDs[:], &cbNeeded)
	if err != nil {
		return nil, fmt.Errorf("could not enumerate processes: %v", err)
	}

	numProcesses := cbNeeded / uint32(unsafe.Sizeof(processIDs[0]))
	var matchingProcesses []uint32
	for i := 0; i < int(numProcesses); i++ {
		processID := processIDs[i]

		hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
		if err != nil {
			continue
		}

		var buffer [1024]uint16
		err = windows.GetModuleFileNameEx(hProcess, 0, &buffer[0], 1024)
		if err != nil {
			continue
		}

		exeName := syscall.UTF16ToString(buffer[:])
		if strings.Contains(exeName, processName) {
			matchingProcesses = append(matchingProcesses, processID)
		}
		windows.CloseHandle(hProcess)
	}

	return matchingProcesses, nil
}

func getModule(modName string, procID uint32) (windows.ModuleEntry32, error) {
	var modEntry windows.ModuleEntry32
	modEntry.Size = uint32(unsafe.Sizeof(modEntry))

	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, procID)
	if err != nil {
		return modEntry, err
	}
	defer windows.CloseHandle(hSnap)

	err = windows.Module32First(hSnap, &modEntry)
	if err != nil {
		return modEntry, err
	}

	for {
		if windows.UTF16ToString(modEntry.Module[:]) == modName {
			return modEntry, nil
		}
		err = windows.Module32Next(hSnap, &modEntry)
		if err != nil {
			break
		}
	}

	return windows.ModuleEntry32{}, fmt.Errorf("module %s not found", modName)
}

func (m *Memory) CalculateAddress(pointer StaticPointer) int64 {
	base := m.ReadMemoryAtByte8(int64(m.BaseInfo.ModBaseAddr) + pointer.BaseOffset)
	var value int64 = int64(base)
	for _, val := range pointer.Offsets {
		value = int64(m.ReadMemoryAtByte8(value + int64(val)))
	}

	if pointer.LastOff != 0 {
		return value + int64(pointer.LastOff)
	}

	return value
}

func (m *Memory) CalculateAddressEx(address uintptr, pointer StaticPointer) uintptr {
	value := m.ReadMemoryAtByte8(int64(address))
	for _, val := range pointer.Offsets {
		value = uintptr(m.ReadMemoryAtByte8(int64(value) + int64(val)))
	}

	if pointer.LastOff != 0 {
		return uintptr(int64(value) + int64(pointer.LastOff))
	}

	return value
}

func (m *Memory) ReadMemoryAtByte8(address int64) uintptr {
	var (
		data   [8]byte
		length uint32
	)

	m.rpm.Call(
		uintptr(m.ProcHandle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	byte8 := binary.LittleEndian.Uint64(data[:])
	return uintptr(byte8)
}
