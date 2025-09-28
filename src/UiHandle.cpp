/* 
 * UiHandle.cpp - Implementation of user interface handle
 *
 * Responsibilities:
 * - Text console UI
 * - Data validation
 * - UI scripts execution
 *
 * -std=c++11
 *
 * LPM 27.09.2025 refined
 */

#include <iostream>
#include "../cryptopp/secblock.h"
#include "AppDataService.h"

/* UI scripts */
void reveal();
void insert();
void remove();
void manual();
void finish();

void showUI()
{
	system("cls");
	cout << " ==================================================================================\n"
		 << " @                           ~ LOCAL PASSWORD MANAGER ~                           @\n"
		 << " ==================================================================================\n"
		 << " 1. Get saved passwords\n"
		 << " 2. Save new password\n"
		 << " 3. Delete saved password\n"
		 << " 4. Show info\n"
		 << " 5. Exit\n"
		 << " Enter your choice (1 - 5): ";
}

void syspause()
{
	cout << "Press any key to continue...";
	_getch();
}

int main()
{	
	/* check if all file sources are available */
	{
		ifstream dataCheck(dataPath);
		if (!dataCheck)
		{
			cout << "data.txt is not available" << endl;
			return 1;
		}
		
		dataCheck.close();
		
		ifstream keyCheck(keysPath);
		if (!keyCheck)
		{
			cout << "keys.txt is not available" << endl;
			return 1;
		}
		
		keyCheck.close();
	}
	
	cout << "\033[?1049h";
	
	while (true)
	{
		showUI();

		string userInput;
		getline(cin, userInput);

		int value;

		try 
		{
			value = stoi(userInput); 
		}

		catch (const exception &exc) 
		{ 
			continue; 
		}
			
		switch (value)
		{
			case 1: reveal(); break;		
			case 2: insert(); break;
			case 3: remove(); break;
			case 4: manual(); break;
			case 5: finish(); return 0;
			default: break;
		}
	}

	return 0;
}

void reveal()
{
	system("cls");

	cout << "Available password sources | type -q to exit" << endl;

	int loaded = printAvailable();
	if (loaded == -1)
	{
		cout << "printAvailable(): cannot open the data file" << endl;
		syspause();
		return;
	}

	else if (loaded == 0)
	{
		cout << "printAvailable(): No sources available. Insert some fisrt" << endl;
		syspause();
		return;
	}

	int sourceNum;
	while (true)
	{
		cout << "enter your choice: ";

		string userInput;
		getline(cin, userInput);

		if (userInput == "")
		{
			cout << "cannot be empty" << endl;
			continue;
		}

		else if (userInput == "-q") return;

		try 
		{
			sourceNum = stoi(userInput); 
		}

		catch (const exception &exc) 
		{
			cout << "not a number" << endl;
			continue; 
		}

		if (0 > sourceNum || sourceNum > loaded - 1)
		{
			cout << "invalid source number" << endl;
			continue;
		}

		break;
	}

	system("cls");

	try
	{
		SecByteBlock plaintext(INPUTLIM);

		string login = decryptFromFile(plaintext, sourceNum);

		cout << "your login is: " << login << endl;

		cout << "your password is: ";

		for (int i = 0; i < plaintext.size() && plaintext[i] != 0x00; i++)
			cout << static_cast<char>(plaintext[i]);

		cout << endl;
	}

	catch (const Exception &exc)
	{
		cout << "reveal(): " << exc.what() << endl;
	}

	catch (const exception &exc)
	{
		cout << "reveal(): " << exc.what() << endl;
	}

	syspause();
}

void insert()
{
	system("cls");
	
	cout << "Insert new pass form (32 chars limit) | press Esc to finish" << endl;
	
	string newSource;
			
	while (true)
	{
		cout << "Enter new source: ";

		if (inputRead(newSource))
			return;

		if (newSource.empty())
		{
			cout << "cannot be empty" << endl;
			continue;
		}

		break;
	}

	string newLogin;

	while (true)
	{
		cout << "Enter new login: ";

		if (inputRead(newLogin))
			return;

		if (newLogin.empty())
		{
			cout << "cannot be empty" << endl;
			continue;
		}

		break;
	}

	try
	{
		SecByteBlock newPassword(0, INPUTLIM);

		while (true)
		{
			cout << "Enter new password: ";
		
			if (secureInputRead(newPassword))
				return;
		
			if (newPassword[0] == 0x00)
			{
				cout << "cannot be empty" << endl;
				continue;
			}
				
			break;
		}
	
		system("cls");

		encryptIntoFile(newSource, newLogin, newPassword);
		cout << "successfully added" << endl;
	}
	
	catch (const Exception &exc)
	{
		cout << "insert(): " << exc.what() << endl;
	}

	catch (const exception &exc)
	{
		cout << "insert(): " << exc.what() << endl;
	}

	syspause();
}

void remove()
{
	system("cls");

	cout << "Available password sources | type -q to exit" << endl;

	int loaded = printAvailable();
	if (loaded == -1)
	{
		cout << "printAvailable(): cannot open the data file" << endl;
		syspause();
		return;
	}

	else if (loaded == 0)
	{
		cout << "printAvailable(): No sources available. Insert some fisrt" << endl;
		syspause();
		return;
	}

	int sourceNum;
	while (true)
	{
		cout << "enter your choice: ";

		string userInput;
		getline(cin, userInput);

		if (userInput == "")
		{
			cout << "cannot be empty" << endl;
			continue;
		}

		else if (userInput == "-q") return;

		try 
		{
			sourceNum = stoi(userInput); 
		}

		catch (const exception &exc) 
		{
			cout << "not a number" << endl;
			continue; 
		}

		if (0 > sourceNum || sourceNum > loaded - 1)
		{
			cout << "invalid source number" << endl;
			continue;
		}

		cout << "Are you sure you want to delete this source? No recover provided [Y/n]: ";

		string confirm;
		getline(cin, confirm);

		if (confirm == "Y" || confirm == "y")
			break;

		else
		{
			cout << "aborted" << endl;
			continue;
		}
	}

	system("cls");

	int res = deleteSource(sourceNum);

	if (res == -1)
		cout << "deleteSource(): cannot open the keys file" << endl;

	else
		cout << "successfully deleted" << endl;

	syspause();
}

void manual()
{
	system("cls");

	ifstream docFile("../manual.txt");

	if (!docFile.is_open())
		cout << "cannot open manual.txt file" << endl;

	else
	{
		string line;
		while (getline(docFile, line))
		{	
			cout << line << endl;
			line.clear();
		}
	}

	cout << endl;
	syspause();
}

void finish()
{
	system("cls");
	cout << "\033[?1049l";
}

/* _EOF_ */