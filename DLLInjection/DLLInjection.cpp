#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>

#define DEBUG
#undef DEBUG

int main()
{

	using namespace std;

	cout << "Injector" << "\n\n";

	//Nombre del proceso.
	const WCHAR* processName = L"TemperatureAnalizer.exe";

	//Ruta del archivo dll.
	char dllPath[MAX_PATH] = "C:\\Users\\xstar\\source\\repos\\DLLInjection\\x64\\Debug\\TestDLL.dll";

	DWORD processId = 0;

	/*PROCESSENTRY32.Representa un proceso de una lista de procesos.*/
	PROCESSENTRY32 processEntry{};

	/*Establecemos el tamaño en bytes del objeto.Es necesario para que 
	la función Process32First funcione.*/
	processEntry.dwSize = sizeof(processEntry);

	/*Registramos todos los procesos que estén en ejecución en el sistema.
	Cualquier proceso que se ejecute luego crear los registros, no se incluirá
	en estos. El argumento TH32CS_SNAPPROCESS es un entero que indica que se
	registrarán todos los procesos en ejecución; el valor de 0 representa el
	id del proceso a registrar, que en este caso es ignorado.*/
	const HANDLE hSnapshotObj = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//Revisamos si los no registros se crearon.
	if (hSnapshotObj == INVALID_HANDLE_VALUE)
	{

		cout << "Valor del Handle inválido." << endl;
		return -1;

	}

	/*Obtenemos el primer proceso de los registros y guardamos su informacion en
	processEntry, hProcessEntries indica */
	if (!Process32First(hSnapshotObj, &processEntry))
	{

		CloseHandle(hSnapshotObj);

		cout << "Ha ocurrido un error en la función Process32First.\n";

		if (GetLastError() == ERROR_NO_MORE_FILES)
			cout << "No existen procesos o el snapshot no registró ningún proceso." << endl;

		return -1;

	}

	//Recorremos todos los procesos en busca del que necesitamos.
	do
	{

#ifdef DEBUG

		wcout << "Process Name: " << processEntry.szExeFile << "\n";

#endif

		/*Comparamos si el nombre del proceso actual es igual al nombre del
		proceso que buscamos.*/
		if (wcscmp(processEntry.szExeFile, processName) == 0)
		{

			//Actualizamos el Id del proceso encontrado.
			processId = processEntry.th32ProcessID;

			if (!processId)
				continue;

			//Mostramos los datos del proceso encontrado.
			wcout << "Proceso: " << processName << "\n";
			wcout << "ID del proceso: " << processId << "\n\n";

			//Abrimos el Handle del proceso para poder usarlo en código.
			const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

			//Revisamos si ocurrió un error.
			if (hProcess == INVALID_HANDLE_VALUE)
			{

				wcout << "Ocurrió un error al abrir el Handle del proceso.";
				return -1;

			}

			wcout << "HANDLE del proceso: " << hProcess << "\n\n";

			/*Alocamos y reservamos una parte de la memoria virtual del proceso en la que estará la ruta del DLL.
			Obtenemos la dirección del buffer creado. Nota: el tipo LPVOID es específico de Windows, pero equivale
			a un void*.*/		
			void* bufferAddress = VirtualAllocEx(hProcess, nullptr, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			//Revisamos si huvo un error al realizar la operación anterior.
			if (!bufferAddress)
			{

				wcout << "No se pudo escribir el DLL en la memoria del proceso." << endl;
				return -1;

			}

			wcout << "Se creó el espacio de memoria para el DLL.\n\n";

			/*Insertamos la ruta del dll en la memoria del proceso, la cual se inserta en la dirección del buffer
			creado y la longitud de la información a insertar es la de la ruta. El argumento con valor nullptr es
			para que, opcionalmente, registremos la cantidad de bytes escritos.*/
			const DWORD dwWriteResult = WriteProcessMemory(hProcess, bufferAddress, dllPath, strlen(dllPath) + 1, nullptr);

			//Revisamos si hubo un error en la inserción.
			if (dwWriteResult == 0)
			{

				wcout << "Hubo un error en la inserción de la ruta del DLL." << endl;
				return -1;

			}

			wcout << "Se injectó el DLL." << "\n\n";

			/*Creamos un hilo en el proceso que va a cargar el DLL en el mismo. Para eso, vamos a llamar a la función 
			"LoadLibrary" en el proceso nuevo, en el archivo kernel32.dll, la cual va cargar el DLL. Esta función
			lee la ruta en el buffer y crea un módulo que ejecuta el DLL.*/
			const HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
				(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"),
				bufferAddress, 0, nullptr);

			//ResumeThread(hThread);
			
			if (!hThread)
			{

				wcout << "Hubo un error en la creación del hilo." << endl;
				return -1;

			}

			wcout << "Se creó el hilo.\nSe terminó la injección del DLL." << endl;

			CloseHandle(hProcess);
			CloseHandle(hThread);

			break;

		}

	} while (Process32Next(hSnapshotObj, &processEntry));

	CloseHandle(hSnapshotObj);
	

	std::cin.get();

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menuv

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
