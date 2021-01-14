/*
 * 2018 crash issue fix
 * Written by: faith
 *
 */

#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>
#include <vector>

#include "min_hook/min_hook.h"

void* og_calculate_allocation_size = nullptr;

 // The game is crashing when it's allocating an invalid amount of memory
 // It's getting this amount from the function below, I am just hooking the function
 // and returning 0.

std::uint16_t calculate_allocation_size( ) {
	return 0;
}

// Pattern scan utility function
// This is not written by me, I don't know it's origin

std::uint8_t* pattern_scan( void* module, const char* signature ) {
	static auto pattern_to_byte = [ ]( const char* pattern ) {
		auto bytes = std::vector<int>{};
		auto start = const_cast< char* >( pattern );
		auto end = const_cast< char* >( pattern ) + strlen( pattern );

		for ( auto current = start; current < end; ++current ) {
			if ( *current == '?' ) {
				++current;
				if ( *current == '?' )
					++current;
				bytes.push_back( -1 );
			}
			else {
				bytes.push_back( strtoul( current, &current, 16 ) );
			}
		}
		return bytes;
	};

	auto dos_headers = static_cast< PIMAGE_DOS_HEADER >( module );
	auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >( static_cast< std::uint8_t* >( module ) + dos_headers->e_lfanew );

	auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	auto pattern_bytes = pattern_to_byte( signature );
	auto scan_bytes = static_cast< std::uint8_t* >( module );

	auto s = pattern_bytes.size( );
	auto d = pattern_bytes.data( );

	for ( auto i = 0ul; i < size_of_image - s; ++i ) {
		bool found = true;
		for ( auto j = 0ul; j < s; ++j ) {
			if ( scan_bytes[ i + j ] != d[ j ] && d[ j ] != -1 ) {
				found = false;
				break;
			}
		}
		if ( found ) {
			return &scan_bytes[ i ];
		}
	}
	
	return nullptr;
}

DWORD init_thread( ) {
	// Setup min hook
	if ( MH_Initialize( ) != MH_OK ) {
		return 0;
	}

	// The signature is pointing to a call with a relative offset to the function in question (E8)
	const auto relative_offset_ptr = pattern_scan( GetModuleHandleA( "client.dll" ), "E8 ? ? ? ? 0F BF C8" ) + 1;

	MH_CreateHook( relative_offset_ptr + *reinterpret_cast< uintptr_t* >( relative_offset_ptr ) +4, calculate_allocation_size, &og_calculate_allocation_size );
	MH_EnableHook( MH_ALL_HOOKS );
	
	return 0;
}

BOOL WINAPI DllMain( HINSTANCE handle_inst_dll, DWORD reason, LPVOID reserved ) {
	if ( reason == DLL_PROCESS_ATTACH ) {
		CreateThread( nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( init_thread ), 0, 0, 0 );
	}

	return TRUE;
}