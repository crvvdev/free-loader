#pragma once

#include <winternl.h>

#ifndef _NTDEF_
typedef _Return_type_success_( return >= 0 ) LONG NTSTATUS;
#endif

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)

#define SEC_NO_CHANGE 0x00400000

#define PAGE_SIZE 0x1000
#define POINTER_IS_ALIGNED(Pointer, Alignment) \
    (((((ULONG_PTR)(Pointer)) & (((Alignment)-1))) == 0) ? TRUE : FALSE)

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

#define  FILE_DEVICE_SCSI              0x0000001b
#define  IOCTL_SCSI_MINIPORT_IDENTIFY  ((FILE_DEVICE_SCSI << 16) + 0x0501)
#define  IOCTL_SCSI_MINIPORT 0x0004D008  //  see NTDDSCSI.H for definition

#define  IDE_ATA_IDENTIFY    0xEC

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x)>=0)
#endif

namespace nt
{
	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		BOOLEAN Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;

		union
		{
			LIST_ENTRY HashLinks;

			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};

		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};

		_ACTIVATION_CONTEXT* EntryPointActivationContext;
		PVOID PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _CURDIR
	{
		UNICODE_STRING DosPath;
		PVOID Handle;
	} CURDIR, * PCURDIR;

	typedef struct _RTL_DRIVE_LETTER_CURDIR
	{
		WORD Flags;
		WORD Length;
		ULONG TimeStamp;
		STRING DosPath;
	} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

	typedef struct _RTL_USER_PROCESS_PARAMETERS
	{
		ULONG MaximumLength;
		ULONG Length;
		ULONG Flags;
		ULONG DebugFlags;
		PVOID ConsoleHandle;
		ULONG ConsoleFlags;
		PVOID StandardInput;
		PVOID StandardOutput;
		PVOID StandardError;
		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PVOID Environment;
		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;
		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectores[ 32 ];
		ULONG EnvironmentSize;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _RTL_CRITICAL_SECTION* PRTL_CRITICAL_SECTION;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifdef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#endif

	typedef ULONG GDI_HANDLE_BUFFER[ GDI_HANDLE_BUFFER_SIZE ];
	typedef ULONG GDI_HANDLE_BUFFER32[ GDI_HANDLE_BUFFER_SIZE32 ];
	typedef ULONG GDI_HANDLE_BUFFER64[ GDI_HANDLE_BUFFER_SIZE64 ];

	// symbols
	typedef struct _PEB
	{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;

		union
		{
			BOOLEAN BitField;

			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN SpareBits : 1;
			};
		};

		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
		PVOID AtlThunkSListPtr;
		PVOID IFEOKey;

		union
		{
			ULONG CrossProcessFlags;

			struct
			{
				ULONG ProcessInJob : 1;
				ULONG ProcessInitializing : 1;
				ULONG ProcessUsingVEH : 1;
				ULONG ProcessUsingVCH : 1;
				ULONG ProcessUsingFTH : 1;
				ULONG ReservedBits0 : 27;
			};

			ULONG EnvironmentUpdateCount;
		};

		union
		{
			PVOID* KernelCallbackTable;
			PVOID UserSharedInfoPtr;
		};

		ULONG SystemReserved[ 1 ];
		ULONG AtlThunkSListPtr32;
		PVOID ApiSetMap;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[ 2 ];
		PVOID ReadOnlySharedMemoryBase;
		PVOID HotpatchInformation;
		PVOID* ReadOnlyStaticServerData;
		PVOID AnsiCodePageData;
		PVOID OemCodePageData;
		PVOID UnicodeCaseTableData;

		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;

		LARGE_INTEGER CriticalSectionTimeout;
		SIZE_T HeapSegmentReserve;
		SIZE_T HeapSegmentCommit;
		SIZE_T HeapDeCommitTotalFreeThreshold;
		SIZE_T HeapDeCommitFreeBlockThreshold;

		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID* ProcessHeaps;

		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		ULONG GdiDCAttributeList;

		PRTL_CRITICAL_SECTION LoaderLock;

		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		USHORT OSBuildNumber;
		USHORT OSCSDVersion;
		ULONG OSPlatformId;
		ULONG ImageSubsystem;
		ULONG ImageSubsystemMajorVersion;
		ULONG ImageSubsystemMinorVersion;
		ULONG_PTR ImageProcessAffinityMask;
		GDI_HANDLE_BUFFER GdiHandleBuffer;
		PVOID PostProcessInitRoutine;

		PVOID TlsExpansionBitmap;
		ULONG TlsExpansionBitmapBits[ 32 ];

		ULONG SessionId;

		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		PVOID pShimData;
		PVOID AppCompatInfo;

		UNICODE_STRING CSDVersion;

		PVOID ActivationContextData;
		PVOID ProcessAssemblyStorageMap;
		PVOID SystemDefaultActivationContextData;
		PVOID SystemAssemblyStorageMap;

		SIZE_T MinimumStackCommit;

		PVOID* FlsCallback;
		LIST_ENTRY FlsListHead;
		PVOID FlsBitmap;
		ULONG FlsBitmapBits[ FLS_MAXIMUM_AVAILABLE / ( sizeof( ULONG ) * 8 ) ];
		ULONG FlsHighIndex;

		PVOID WerRegistrationData;
		PVOID WerShipAssertPtr;
		PVOID pContextData;
		PVOID pImageHeaderHash;

		union
		{
			ULONG TracingFlags;

			struct
			{
				ULONG HeapTracingEnabled : 1;
				ULONG CritSecTracingEnabled : 1;
				ULONG LibLoaderTracingEnabled : 1;
				ULONG SpareTracingBits : 29;
			};
		};

		ULONGLONG CsrServerReadOnlySharedMemoryBase;
	} PEB, * PPEB;

#define GDI_BATCH_BUFFER_SIZE 310

	typedef struct _GDI_TEB_BATCH
	{
		ULONG Offset;
		ULONG_PTR HDC;
		ULONG Buffer[ GDI_BATCH_BUFFER_SIZE ];
	} GDI_TEB_BATCH, * PGDI_TEB_BATCH;


	typedef struct _TEB_ACTIVE_FRAME_CONTEXT
	{
		ULONG Flags;
		PSTR FrameName;
	} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

	typedef struct _TEB_ACTIVE_FRAME
	{
		ULONG Flags;
		struct _TEB_ACTIVE_FRAME* Previous;
		PTEB_ACTIVE_FRAME_CONTEXT Context;
	} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

	typedef struct _ACTIVATION_CONTEXT_STACK
	{
		struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

	typedef struct _TEB
	{
		NT_TIB NtTib;

		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PPEB ProcessEnvironmentBlock;

		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[ 26 ];
		ULONG UserReserved[ 5 ];
		PVOID WOW32Reserved;
		LCID CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		PVOID ReservedForDebuggerInstrumentation[ 16 ];
#ifdef _WIN64
		PVOID SystemReserved1[ 30 ];
#else
		PVOID SystemReserved1[ 26 ];
#endif

		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderReserved[ 11 ];
		ULONG ProxiedProcessId;
		ACTIVATION_CONTEXT_STACK ActivationStack;

		UCHAR WorkingOnBehalfTicket[ 8 ];
		NTSTATUS ExceptionCode;

		PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
		ULONG_PTR InstrumentationCallbackSp;
		ULONG_PTR InstrumentationCallbackPreviousPc;
		ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
		ULONG TxFsContext;
#endif

		BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
		UCHAR SpareBytes[ 23 ];
		ULONG TxFsContext;
#endif
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		HANDLE GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG_PTR Win32ClientInfo[ 62 ];
		PVOID glDispatchTable[ 233 ];
		ULONG_PTR glReserved1[ 29 ];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;

		NTSTATUS LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[ 261 ];

		PVOID DeallocationStack;
		PVOID TlsSlots[ 64 ];
		LIST_ENTRY TlsLinks;

		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[ 2 ];

		ULONG HardErrorMode;
#ifdef _WIN64
		PVOID Instrumentation[ 11 ];
#else
		PVOID Instrumentation[ 9 ];
#endif
		GUID ActivityId;

		PVOID SubProcessTag;
		PVOID PerflibData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;

		union
		{
			PROCESSOR_NUMBER CurrentIdealProcessor;
			ULONG IdealProcessorValue;

			struct
			{
				UCHAR ReservedPad0;
				UCHAR ReservedPad1;
				UCHAR ReservedPad2;
				UCHAR IdealProcessor;
			};
		};

		ULONG GuaranteedStackBytes;
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG_PTR ReservedForCodeCoverage;
		PVOID ThreadPoolData;
		PVOID* TlsExpansionSlots;
#ifdef _WIN64
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
#endif
		ULONG MuiGeneration;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		USHORT HeapVirtualAffinity;
		USHORT LowFragHeapDataSlot;
		HANDLE CurrentTransactionHandle;
		PTEB_ACTIVE_FRAME ActiveFrame;
		PVOID FlsData;

		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;

		union
		{
			USHORT CrossTebFlags;
			USHORT SpareCrossTebBits : 16;
		};

		union
		{
			USHORT SameTebFlags;

			struct
			{
				USHORT SafeThunkCall : 1;
				USHORT InDebugPrint : 1;
				USHORT HasFiberData : 1;
				USHORT SkipThreadAttach : 1;
				USHORT WerInShipAssertCode : 1;
				USHORT RanProcessInit : 1;
				USHORT ClonedThread : 1;
				USHORT SuppressDebugMsg : 1;
				USHORT DisableUserStackWalk : 1;
				USHORT RtlExceptionAttached : 1;
				USHORT InitialThread : 1;
				USHORT SessionAware : 1;
				USHORT LoadOwner : 1;
				USHORT LoaderWorker : 1;
				USHORT SkipLoaderInit : 1;
				USHORT SpareSameTebBits : 1;
			};
		};

		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		LONG WowTebOffset;
		PVOID ResourceRetValue;
		PVOID ReservedForWdf;
		ULONGLONG ReservedForCrt;
		GUID EffectiveContainerId;
	} TEB, * PTEB;

	typedef struct _KSYSTEM_TIME
	{
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, * PKSYSTEM_TIME;

	typedef enum _NT_PRODUCT_TYPE
	{
		NtProductWinNt = 1,
		NtProductLanManNt = 2,
		NtProductServer = 3
	} NT_PRODUCT_TYPE;

	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
	{
		StandardDesign = 0,
		NEC98x86 = 1,
		EndAlternatives = 2
	} ALTERNATIVE_ARCHITECTURE_TYPE;

	typedef struct _KUSER_SHARED_DATA
	{
		ULONG TickCountLowDeprecated;
		ULONG TickCountMultiplier;

		volatile KSYSTEM_TIME InterruptTime;
		volatile KSYSTEM_TIME SystemTime;
		volatile KSYSTEM_TIME TimeZoneBias;

		USHORT ImageNumberLow;
		USHORT ImageNumberHigh;

		WCHAR NtSystemRoot[ 260 ];

		ULONG MaxStackTraceDepth;

		ULONG CryptoExponent;

		ULONG TimeZoneId;
		ULONG LargePageMinimum;
		ULONG AitSamplingValue;
		ULONG AppCompatFlag;
		ULONGLONG RNGSeedVersion;
		ULONG GlobalValidationRunlevel;
		LONG TimeZoneBiasStamp;

		ULONG NtBuildNumber;
		NT_PRODUCT_TYPE NtProductType;
		BOOLEAN ProductTypeIsValid;
		UCHAR Reserved0[ 1 ];
		USHORT NativeProcessorArchitecture;

		ULONG NtMajorVersion;
		ULONG NtMinorVersion;

		BOOLEAN ProcessorFeatures[ 64 ];

		ULONG Reserved1;
		ULONG Reserved3;

		volatile ULONG TimeSlip;

		ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
		ULONG BootId;

		LARGE_INTEGER SystemExpirationDate;

		ULONG SuiteMask;

		BOOLEAN KdDebuggerEnabled;

		union
		{
			UCHAR MitigationPolicies;

			struct
			{
				UCHAR NXSupportPolicy : 2;
				UCHAR SEHValidationPolicy : 2;
				UCHAR CurDirDevicesSkippedForDlls : 2;
				UCHAR Reserved : 2;
			};
		};

		USHORT CyclesPerYield;

		volatile ULONG ActiveConsoleId;

		volatile ULONG DismountCount;

		ULONG ComPlusPackage;

		ULONG LastSystemRITEventTickCount;

		ULONG NumberOfPhysicalPages;

		BOOLEAN SafeBootMode;
		UCHAR VirtualizationFlags;
		UCHAR Reserved12[ 2 ];

		union
		{
			ULONG SharedDataFlags;

			struct
			{
				ULONG DbgErrorPortPresent : 1;
				ULONG DbgElevationEnabled : 1;
				ULONG DbgVirtEnabled : 1;
				ULONG DbgInstallerDetectEnabled : 1;
				ULONG DbgLkgEnabled : 1;
				ULONG DbgDynProcessorEnabled : 1;
				ULONG DbgConsoleBrokerEnabled : 1;
				ULONG DbgSecureBootEnabled : 1;
				ULONG DbgMultiSessionSku : 1;
				ULONG DbgMultiUsersInSessionSku : 1;
				ULONG DbgStateSeparationEnabled : 1;
				ULONG SpareBits : 21;
			};
		};

		ULONG DataFlagsPad[ 1 ];

		ULONGLONG TestRetInstruction;
		LONGLONG QpcFrequency;
		ULONG SystemCall;
		ULONG SystemCallPad0;
		ULONGLONG SystemCallPad[ 2 ];

		union
		{
			volatile KSYSTEM_TIME TickCount;
			volatile ULONG64 TickCountQuad;
			ULONG ReservedTickCountOverlay[ 3 ];
		};

		ULONG TickCountPad[ 1 ];

		ULONG Cookie;
		ULONG CookiePad[ 1 ];

		LONGLONG ConsoleSessionForegroundProcessId;
		ULONGLONG TimeUpdateLock;
		ULONGLONG BaselineSystemTimeQpc;
		ULONGLONG BaselineInterruptTimeQpc;
		ULONGLONG QpcSystemTimeIncrement;
		ULONGLONG QpcInterruptTimeIncrement;
		UCHAR QpcSystemTimeIncrementShift;
		UCHAR QpcInterruptTimeIncrementShift;

		USHORT UnparkedProcessorCount;
		ULONG EnclaveFeatureMask[ 4 ];

		ULONG TelemetryCoverageRound;

		USHORT UserModeGlobalLogger[ 16 ];
		ULONG ImageFileExecutionOptions;

		ULONG LangGenerationCount;
		ULONGLONG Reserved4;
		volatile ULONG64 InterruptTimeBias;
		volatile ULONG64 QpcBias;

		ULONG ActiveProcessorCount;
		volatile UCHAR ActiveGroupCount;
		UCHAR Reserved9;

		union
		{
			USHORT QpcData;

			struct
			{
				UCHAR QpcBypassEnabled : 1;
				UCHAR QpcShift : 1;
			};
		};

		LARGE_INTEGER TimeZoneBiasEffectiveStart;
		LARGE_INTEGER TimeZoneBiasEffectiveEnd;
		XSTATE_CONFIGURATION XState;
	} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;
}

#pragma pack( push, 1)

// The following struct defines the interesting part of the IDENTIFY
// buffer:
typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[ 3 ];
	CHAR    sSerialNumber[ 20 ];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[ 8 ];
	CHAR    sModelNumber[ 40 ];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[ 128 ];
} IDSECTOR, * PIDSECTOR;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[ 3 ];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[ 8 ];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, * PSRB_IO_CONTROL;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
	GUID BootIdentifier;
	FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

typedef struct _SYSTEM_MODULE
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[ 256 ];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[ 1 ];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _IDENTIFY_DATA
{
	USHORT GeneralConfiguration;            // 00 00
	USHORT NumberOfCylinders;               // 02  1
	USHORT Reserved1;                       // 04  2
	USHORT NumberOfHeads;                   // 06  3
	USHORT UnformattedBytesPerTrack;        // 08  4
	USHORT UnformattedBytesPerSector;       // 0A  5
	USHORT SectorsPerTrack;                 // 0C  6
	USHORT VendorUnique1[ 3 ];                // 0E  7-9
	USHORT SerialNumber[ 10 ];                // 14  10-19
	USHORT BufferType;                      // 28  20
	USHORT BufferSectorSize;                // 2A  21
	USHORT NumberOfEccBytes;                // 2C  22
	USHORT FirmwareRevision[ 4 ];             // 2E  23-26
	USHORT ModelNumber[ 20 ];                 // 36  27-46
	UCHAR  MaximumBlockTransfer;            // 5E  47
	UCHAR  VendorUnique2;                   // 5F
	USHORT DoubleWordIo;                    // 60  48
	USHORT Capabilities;                    // 62  49
	USHORT Reserved2;                       // 64  50
	UCHAR  VendorUnique3;                   // 66  51
	UCHAR  PioCycleTimingMode;              // 67
	UCHAR  VendorUnique4;                   // 68  52
	UCHAR  DmaCycleTimingMode;              // 69
	USHORT TranslationFieldsValid : 1;        // 6A  53
	USHORT Reserved3 : 15;
	USHORT NumberOfCurrentCylinders;        // 6C  54
	USHORT NumberOfCurrentHeads;            // 6E  55
	USHORT CurrentSectorsPerTrack;          // 70  56
	ULONG  CurrentSectorCapacity;           // 72  57-58
	USHORT CurrentMultiSectorSetting;       //     59
	ULONG  UserAddressableSectors;          //     60-61
	USHORT SingleWordDMASupport : 8;        //     62
	USHORT SingleWordDMAActive : 8;
	USHORT MultiWordDMASupport : 8;         //     63
	USHORT MultiWordDMAActive : 8;
	USHORT AdvancedPIOModes : 8;            //     64
	USHORT Reserved4 : 8;
	USHORT MinimumMWXferCycleTime;          //     65
	USHORT RecommendedMWXferCycleTime;      //     66
	USHORT MinimumPIOCycleTime;             //     67
	USHORT MinimumPIOCycleTimeIORDY;        //     68
	USHORT Reserved5[ 2 ];                    //     69-70
	USHORT ReleaseTimeOverlapped;           //     71
	USHORT ReleaseTimeServiceCommand;       //     72
	USHORT MajorRevision;                   //     73
	USHORT MinorRevision;                   //     74
	USHORT Reserved6[ 50 ];                   //     75-126
	USHORT SpecialFunctionsEnabled;         //     127
	USHORT Reserved7[ 128 ];                  //     128-255
} IDENTIFY_DATA, * PIDENTIFY_DATA;

#pragma pack( pop )

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;


EXTERN_C
NTSTATUS
NTAPI
NtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);

EXTERN_C
NTSTATUS
NTAPI
NtMapViewOfSection(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID * BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

EXTERN_C
NTSTATUS
NTAPI
NtUnmapViewOfSection(
	_In_        HANDLE  ProcessHandle,
	_In_opt_    PVOID   BaseAddress
);

EXTERN_C
NTSTATUS
NTAPI
NtClose(
	_In_ HANDLE Handle
);

EXTERN_C
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID BaseAddress
);