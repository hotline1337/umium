# Umium

Class containing Anti-RE, Anti-Debug and Anti-Hook methods. Easy to use and easy to implement.

## Disclaimer

This code has been made and optimized for a [C++/CLI](https://docs.microsoft.com/en-us/cpp/dotnet/dotnet-programming-with-cpp-cli-visual-cpp?view=msvc-160) runtime.

## Usage

```cpp
#include "umium.h"

// any form of a function
// my example
std::function<void(void)> check = [&]()
{
    umium::security::anti_attach();
}

auto main(void)
{
    Console::WriteLine("Starting multi-thread");
    multi_thread obj([]
    {
	    check();
	    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
    Console::ReadKey();
}


```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicens.com/licenses/mit/)
