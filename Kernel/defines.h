#define dbg( content, ... ) DbgPrintEx( 0, 0, "[>] " content, __VA_ARGS__ )
#define rva(instruction, size) ( instruction + size + *reinterpret_cast<long*>(instruction + (size - sizeof(long))))
#define size_align(size) ((size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_c(ch) ((ch >= 'A' && ch <= 'Z') ? (ch + 32) : ch)

#include <ntddmou.h>

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE section;
	PVOID mapped_base;
	PVOID image_base;
	ULONG image_size;
	ULONG flags;
	USHORT load_order_index;
	USHORT init_order_index;
	USHORT load_count;
	USHORT offset_to_file_name;
	UCHAR  full_path_name[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG number_of_modules;
	RTL_PROCESS_MODULE_INFORMATION modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	system_basic_information,
	system_processor_information,
	system_performance_information,
	system_time_of_day_information,
	system_path_information,
	system_process_information,
	system_call_count_information,
	system_device_information,
	system_processor_performance_information,
	system_flags_information,
	system_call_time_information,
	system_module_information,
	system_locks_information,
	system_stack_trace_information,
	system_paged_pool_information,
	system_non_paged_pool_information,
	system_handle_information,
	system_object_information,
	system_page_file_information,
	system_vdm_instemul_information,
	system_vdm_bop_information,
	system_file_cache_information,
	system_pool_tag_information,
	system_interrupt_information,
	system_dpc_behavior_information,
	system_full_memory_information,
	system_load_gdi_driver_information,
	system_unload_gdi_driver_information,
	system_time_adjustment_information,
	system_summary_memory_information,
	system_next_event_id_information,
	system_event_ids_information,
	system_crash_dump_information,
	system_exception_information,
	system_crash_dump_state_information,
	system_kernel_debugger_information,
	system_context_switch_information,
	system_registry_quota_information,
	system_extend_service_table_information,
	system_priority_seperation,
	system_plug_play_bus_information,
	system_dock_information,
	system_processor_speed_information,
	system_current_time_zone_information,
	system_lookaside_information,
	system_bigpool_information = 0x42
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef  enum
{
	PS_COSMETIC = 0x00000000,
	PS_ENDCAP_ROUND = 0x00000000,
	PS_JOIN_ROUND = 0x00000000,
	PS_SOLID = 0x00000000,
	PS_DASH = 0x00000001,
	PS_DOT = 0x00000002,
	PS_DASHDOT = 0x00000003,
	PS_DASHDOTDOT = 0x00000004,
	PS_NULL = 0x00000005,
	PS_INSIDEFRAME = 0x00000006,
	PS_USERSTYLE = 0x00000007,
	PS_ALTERNATE = 0x00000008,
	PS_ENDCAP_SQUARE = 0x00000100,
	PS_ENDCAP_FLAT = 0x00000200,
	PS_JOIN_BEVEL = 0x00001000,
	PS_JOIN_MITER = 0x00002000,
	PS_GEOMETRIC = 0x00010000
} PenStyle;

typedef struct {
	LONG lfHeight;
	LONG lfWidth;
	LONG lfEscapement;
	LONG lfOrientation;
	LONG lfWeight;
	BYTE lfItalic;
	BYTE lfUnderline;
	BYTE lfStrikeOut;
	BYTE lfCharSet;
	BYTE lfOutPrecision;
	BYTE lfClipPrecision;
	BYTE lfQuality;
	BYTE lfPitchAndFamily;
	WCHAR lfFaceName[32];
} LOGFONTW;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY in_load_order_links;
	LIST_ENTRY in_memory_order_links;
	LIST_ENTRY in_initialization_order_links;
	PVOID dll_base;
	PVOID entry_point;
	ULONG size_of_image;
	UNICODE_STRING full_dll_name;
	UNICODE_STRING base_dll_name;
	ULONG flags;
	WORD load_count;
	WORD tls_index;
	union
	{
		LIST_ENTRY hash_links;
		struct
		{
			PVOID section_pointer;
			ULONG check_sum;
		};
	};
	union
	{
		ULONG time_date_stamp;
		PVOID loaded_imports;
	};
	void *entry_point_activation_context;
	PVOID patch_information;
	LIST_ENTRY forwarder_links;
	LIST_ENTRY service_tag_links;
	LIST_ENTRY static_links;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_CRITICAL_SECTION
{
	void *debug_info;
	LONG lock_count;
	LONG recursion_count;
	PVOID owning_thread;
	PVOID lock_semaphore;
	ULONG spin_count;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef struct _PEB_LDR_DATA
{
	ULONG length;
	UCHAR initialized;
	PVOID ss_handle;
	LIST_ENTRY in_load_order_module_list;
	LIST_ENTRY in_memory_order_module_list;
	LIST_ENTRY in_initialization_order_module_list;
	PVOID entry_in_progress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR inherited_address_space;
	UCHAR read_image_file_exec_options;
	UCHAR being_debugged;
	UCHAR bit_field;
	ULONG image_uses_large_pages : 1;
	ULONG is_protected_process : 1;
	ULONG is_legacy_process : 1;
	ULONG is_image_dynamically_relocated : 1;
	ULONG spare_bits : 4;
	PVOID mutant;
	PVOID image_base_address;
	PPEB_LDR_DATA ldr;
	void *process_parameters;
	PVOID sub_system_data;
	PVOID process_heap;
	PRTL_CRITICAL_SECTION fast_peb_lock;
	PVOID atl_thunk_s_list_ptr;
	PVOID ifeo_key;
	ULONG cross_process_flags;
	ULONG process_in_job : 1;
	ULONG process_initializing : 1;
	ULONG reserved_bits0 : 30;
	union
	{
		PVOID kernel_callback_table;
		PVOID user_shared_info_ptr;
	};
	ULONG system_reserved[1];
	ULONG spare_ulong;
	void *free_list;
	ULONG tls_expansion_counter;
	PVOID tls_bitmap;
	ULONG tls_bitmap_bits[2];
	PVOID read_only_shared_memory_base;
	PVOID hotpatch_information;
	void **read_only_static_server_data;
	PVOID ansi_code_page_data;
	PVOID oem_code_page_data;
	PVOID unicode_case_table_data;
	ULONG number_of_processors;
	ULONG nt_global_flag;
	LARGE_INTEGER critical_section_timeout;
	ULONG heap_segment_reserve;
	ULONG heap_segment_commit;
	ULONG heap_de_commit_total_free_threshold;
	ULONG heap_de_commit_free_block_threshold;
	ULONG number_of_heaps;
	ULONG maximum_number_of_heaps;
	void **process_heaps;
	PVOID gdi_shared_handle_table;
	PVOID process_starter_helper;
	ULONG gdi_dc_attribute_list;
	PRTL_CRITICAL_SECTION loader_lock;
	ULONG os_major_version;
	ULONG os_minor_version;
	WORD os_build_number;
	WORD oscsd_version;
	ULONG os_platform_id;
	ULONG image_subsystem;
	ULONG image_subsystem_major_version;
	ULONG image_subsystem_minor_version;
	ULONG image_process_affinity_mask;
	ULONG gdi_handle_buffer[34];
	PVOID post_process_init_routine;
	PVOID tls_expansion_bitmap;
	ULONG tls_expansion_bitmap_bits[32];
	ULONG session_id;
	ULARGE_INTEGER app_compat_flags;
	ULARGE_INTEGER app_compat_flags_user;
	PVOID p_shim_data;
	PVOID app_compat_info;
	UNICODE_STRING csd_version;
	void *activation_context_data;
	void *process_assembly_storage_map;
	void *system_default_activation_context_data;
	void *system_assembly_storage_map;
	ULONG minimum_stack_commit;
	void *fls_callback;
	LIST_ENTRY fls_list_head;
	PVOID fls_bitmap;
	ULONG fls_bitmap_bits4[4];
	ULONG fls_high_index;
	void* wer_registration_data;
	void* wer_ship_assert_ptr;
} PEB, *PPEB;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER kernel_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER create_time;
	ULONG wait_time;
	PVOID start_address;
	CLIENT_ID client_id;
	KPRIORITY priority;
	LONG base_priority;
	ULONG context_switches;
	ULONG thread_state;
	KWAIT_REASON wait_reason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG next_entry_offset;
	ULONG number_of_threads;
	LARGE_INTEGER working_set_private_size;
	ULONG hard_fault_count;
	ULONG number_of_threads_high_watermark;
	ULONGLONG cycle_time;
	LARGE_INTEGER create_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER kernel_time;
	UNICODE_STRING image_name;
	KPRIORITY base_priority;
	HANDLE unique_process_id;
	HANDLE inherited_from_unique_process_id;
	ULONG handle_count;
	ULONG session_id;
	ULONG_PTR unique_process_key;
	SIZE_T peak_virtual_size;
	SIZE_T virtual_size;
	ULONG page_fault_count;
	SIZE_T peak_working_set_size;
	SIZE_T working_set_size;
	SIZE_T quota_peak_paged_pool_usage;
	SIZE_T quota_paged_pool_usage;
	SIZE_T quota_peak_non_paged_pool_usage;
	SIZE_T quota_non_paged_pool_usage;
	SIZE_T pagefile_usage;
	SIZE_T peak_pagefile_usage;
	SIZE_T private_page_count;
	LARGE_INTEGER read_operation_count;
	LARGE_INTEGER write_operation_count;
	LARGE_INTEGER other_operation_count;
	LARGE_INTEGER read_transfer_count;
	LARGE_INTEGER write_transfer_count;
	LARGE_INTEGER other_transfer_count;
	SYSTEM_THREAD_INFORMATION threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef VOID
(*MouseClassServiceCallback)(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
	);

typedef struct _MOUSE_OBJECT
{
	PDEVICE_OBJECT mouse_device;
	MouseClassServiceCallback service_callback;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

extern "C"
{
	POBJECT_TYPE* IoDriverObjectType;

	NTSYSAPI NTSTATUS RtlCreateUserThread( HANDLE, PVOID, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID );
	__declspec( dllimport ) NTSTATUS ZwWaitForMultipleObjects( unsigned long, HANDLE[], WAIT_TYPE, BOOLEAN, LARGE_INTEGER * );
	__declspec( dllimport ) PPEB PsGetProcessPeb( PEPROCESS );
	__declspec( dllimport ) NTSTATUS __stdcall ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS, void *, unsigned long, unsigned long * );
	NTSTATUS __stdcall MmCopyVirtualMemory( PEPROCESS, void *, PEPROCESS, void *, unsigned long long, KPROCESSOR_MODE, unsigned long long * );
	__declspec( dllimport ) void *__stdcall RtlFindExportedRoutineByName( void *, PCCH );
	NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName( _In_ PUNICODE_STRING ObjectName, _In_ ULONG Attributes, _In_opt_ PACCESS_STATE AccessState, _In_opt_ ACCESS_MASK DesiredAccess, _In_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode, _Inout_opt_ PVOID ParseContext, _Out_ PVOID * Object );
}