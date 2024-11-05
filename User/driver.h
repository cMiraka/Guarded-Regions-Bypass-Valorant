#pragma once

class _driver
{
private:
	typedef INT64(*Nt_UserGetPointerProprietaryId)(uintptr_t);
	Nt_UserGetPointerProprietaryId NtUserGetPointerProprietaryId = nullptr;

#define DRIVER_READVM				0x80000001
#define DRIVER_PML4BASE				0x80000002
#define DRIVER_MOUSE				0x80000003

	int _processid;

	struct _requests
	{
		//rw
		uint32_t    src_pid;
		uint64_t    src_addr;
		uint64_t    dst_addr;
		size_t        size;

		//function requests
		int request_key;

		//shadow regions
		uintptr_t pml4_base;

		//mouse
		long x;
		long y;
		unsigned short button_flags;
	};
	
	auto readvm(uint32_t src_pid, uint64_t src_addr, uint64_t dst_addr, size_t size) -> void
	{
		if (src_pid == 0 || src_addr == 0) return;

		_requests out = { src_pid, src_addr, dst_addr, size, DRIVER_READVM };
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
	}

public:
	auto initdriver(int processid) -> void
	{
		NtUserGetPointerProprietaryId = (Nt_UserGetPointerProprietaryId)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetPointerProprietaryId");
		if (NtUserGetPointerProprietaryId != 0)
		{
			printf("NtUserGetPointerProprietaryId: %p\n", NtUserGetPointerProprietaryId);
			_processid = processid;
		}
	}

	auto pml4_base() -> uintptr_t
	{
		_requests out = { 0 };
		out.request_key = DRIVER_PML4BASE;
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
		return out.pml4_base;
	}

	template <typename T>
	T read(uintptr_t src, size_t size = sizeof(T))
	{
		T buffer;
		readvm(_processid, src, (uintptr_t)&buffer, size);
		return buffer;
	}

	template<typename T>
	void readarray(uint64_t address, T* array, size_t len)
	{
		readvm(_processid, address, (uintptr_t)&array, sizeof(T) * len);
	}

	/*
	auto move_mouse(long x, long y) -> void
	{
		_requests out = { 0 };
		out.x = x;
		out.y = y;
		out.request_key = DRIVER_MOUSE;
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
	}

	auto send_input(unsigned short button) -> void
	{
		_requests out = { 0 };
		out.button_flags = button;
		out.request_key = DRIVER_MOUSE;
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
	}*/
};

_driver driver;
