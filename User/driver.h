#pragma once

class _driver
{
private:
	typedef INT64(*Nt_UserGetPointerProprietaryId)(uintptr_t);
	Nt_UserGetPointerProprietaryId NtUserGetPointerProprietaryId = nullptr;

#define DRIVER_READVM				0x80000001
#define DRIVER_GETPOOL				0x80000002
#define DRIVER_MOUSE				0x80000003

	int _processid;
	uint64_t _guardedregion;

	struct _requests
	{
		//rw
		uint32_t    src_pid;
		uint64_t    src_addr;
		uint64_t    dst_addr;
		size_t        size;

		//function requests
		int request_key;

		//guarded regions
		uintptr_t allocation;

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

	auto guarded_region() -> uintptr_t
	{
		_requests out = { 0 };
		out.request_key = DRIVER_GETPOOL;
		NtUserGetPointerProprietaryId(reinterpret_cast<uintptr_t>(&out));
		_guardedregion = out.allocation;
		return out.allocation;
	}

	template <typename T>
	T readguarded(uintptr_t src, size_t size = sizeof(T))
	{
		T buffer;
		readvm(_processid, src, (uintptr_t)&buffer, size);
		uintptr_t val = _guardedregion + (*(uintptr_t*)&buffer & 0xFFFFFF);
		return *(T*)&val;
	}

	template <typename T>
	T readv(uintptr_t src, size_t size = sizeof(T))
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

	//bluefire1337
	inline static bool isguarded(uintptr_t pointer) noexcept
	{
		static constexpr uintptr_t filter = 0xFFFFFFF000000000;
		uintptr_t result = pointer & filter;
		return result == 0x8000000000 || result == 0x10000000000;
	}
	
	template <typename T>
	T read(T src)
	{
		T buffer = readv< uintptr_t >(src);

		if (isguarded((uintptr_t)buffer))
		{
			return readguarded< uintptr_t >(src);
		}

		return buffer;
	}

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
	}
};

_driver driver;
