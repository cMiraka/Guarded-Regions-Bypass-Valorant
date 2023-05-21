#include "imports.h"

auto cachethread() -> void
{
	auto guardedregion = driver.guarded_region();
	printf( "guardedregion: 0x%p\n", guardedregion );

	while (true)
	{
		auto uworld = utils::getuworld( guardedregion );
		printf( "uworld: 0x%p\n", uworld );

		auto ulevel = driver.read< uintptr_t >( uworld  + offsets::ulevel );
		printf( "ulevel: 0x%p\n", ulevel );

		auto gamestate = driver.read< uintptr_t >( uworld + offsets::gamestate );
		printf( "gamestate: 0x%p\n", gamestate );

		Sleep( 2000 );
	}
}

auto main() -> const NTSTATUS
{
	auto process = utils::getprocessid( L"VALORANT-Win64-Shipping.exe" );

	printf( "processid: %i\n", process );

	if ( process != 0 )
	{
		driver.initdriver( process );
		std::thread(cachethread).detach();
	}

	getchar();
	return 0;
}
