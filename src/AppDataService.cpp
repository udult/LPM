/*
 * AppDataService.cpp - Implemention of appdata processing source file
 *
 * Encryption provided with Crypto++ 8.9.0
 * Algo: AES-256 CBC mode
 * -std=c++11
 *
 * LPM 27.09.2025 refined
 */

/* ========== Crypto++ AES proc headers ========== */

#include "../cryptopp/aes.h"
#include "../cryptopp/modes.h"
#include "../cryptopp/osrng.h"

/* ========== Crypto++ transform headers ========== */

#include "../cryptopp/hex.h"
#include "../cryptopp/files.h"
#include "../cryptopp/filters.h"

#include "AppDataService.h"

/* KEY CODES HEX */
constexpr byte ENTER  	 = 0x0D;
constexpr byte ESCAPE 	 = 0x1B;
constexpr byte BACKSPACE = 0x08;

/* ASCII CODES HEX */
constexpr byte ASCII_UPPER_LIM = 0x7E;
constexpr byte ASCII_LOWER_LIM = 0x20;

/* ********** REVEAL PROC FUNCS ********** */
int printAvailable()
{
	ifstream dataFile(dataPath);

	if (!dataFile.is_open())
		return -1;

	string entry;
	string source;

	int count = 0;
	while (getline(dataFile, entry, '|'))
	{
		StringSource(entry, true, 
			new HexDecoder(
				new StringSink(source)
			)
		);

		cout << count++ << " " << source << endl;
		dataFile.ignore(CHARSTOSKIP, '\n');
		source.clear();
	}

	return count;
}

static int secureFileRead(SecByteBlock &iv, SecByteBlock &key, SecByteBlock &cipher, string &login, int lineNum)
{
	ifstream dataFile(dataPath);

	if (!dataFile.is_open())
		return -1;

	ifstream keysFile(keysPath);

	if (!keysFile.is_open())
		return -2;

	int i = 0;
	while (i++ < lineNum)
	{
		dataFile.ignore(CHARSTOSKIP, '\n');
		keysFile.ignore(CHARSTOSKIP, '\n');
	}

	dataFile.ignore(CHARSTOSKIP, '|');

	string loginHex;
	getline(dataFile, loginHex, '|');

	StringSource(loginHex, true,
		new HexDecoder(
			new StringSink(login)
		)
	);

	char ch = '0';
	SecByteBlock cipher_f(0, cipher.size() * 2);
	for (int i = 0; i < cipher_f.size() && ch != '|'; i++)
	{
		dataFile.get(ch);
		cipher_f[i] = (byte) ch;
	}

	ch = '0';
	dataFile.ignore();
	SecByteBlock iv_f(0, iv.size() * 2);
	for (int i = 0; i < iv_f.size() && ch != '\n'; i++)
	{
		dataFile.get(ch);
		iv_f[i] = (byte) ch;
	}

	ch = '0';
	SecByteBlock key_f(0, key.size() * 2);
	for (int i = 0; i < key_f.size() && ch != '\n'; i++)
	{
		keysFile.get(ch);
		key_f[i] = (byte) ch;
	}

	ch = '0';

	ArraySource(cipher_f.data(), cipher_f.size(), true,
		new HexDecoder(
			new ArraySink(cipher.data(), cipher.size())
		)
	);

	ArraySource(iv_f.data(), iv_f.size(), true,
		new HexDecoder(
			new ArraySink(iv.data(), iv.size())
		)
	);

	ArraySource(key_f.data(), key_f.size(), true,
		new HexDecoder(
			new ArraySink(key.data(), key.size())
		)
	);

	return 0;
}

static int isDeleted(SecByteBlock &key)
{
	for (int i = 0; i < key.size(); i++)
		if (key[i] != 0x00) return 0;

	return 1;
}

string decryptFromFile(SecByteBlock &plain, int lineNum)
{
	SecByteBlock cipher(0, INPUTLIM);
	SecByteBlock iv(0, AES::BLOCKSIZE);
	SecByteBlock key(0, AES::MAX_KEYLENGTH);

	string login;
	int res = secureFileRead(iv, key, cipher, login, lineNum);

	if (res == -1)
		throw runtime_error("cannot open the data file");

	else if (res == -2)
		throw runtime_error("cannot open the keys file");
		
	if (isDeleted(key))
		throw runtime_error("password was deleted");
	
	CBC_Mode<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

	ArraySource(cipher.data(), cipher.size(), true,
		new StreamTransformationFilter(decryptor, 
			new ArraySink(plain.data(), plain.size()), StreamTransformationFilter::NO_PADDING
		)
	);

	return login;
}

/* ********** INSERT NEW PROC FUNCS ********** */
int inputRead(string &buffer)
{
	buffer.clear();
	char input = 0x00;

	while (input != ENTER)
	{
		input = static_cast<char>(_getch());

		if (input == ESCAPE)
			return 1;

		else if (input == BACKSPACE)
		{
			if (buffer.size() > 0)
			{
				buffer.pop_back();
				cout << "\b \b";
			}
		}

		else if (ASCII_LOWER_LIM <= input && input <= ASCII_UPPER_LIM)
		{
			if (buffer.size() < INPUTLIM)
			{
				buffer.push_back(input);
				cout << input;
			}
		}
	}

	cout << endl;
	return 0;
}

int secureInputRead(SecByteBlock &buffer)
{
	size_t pos = 0;
	byte input = 0x00;

	while (input != ENTER)
	{
		input = static_cast<byte>(_getch());
		
		if (input == ESCAPE)
			return 1;
			
		else if (input == BACKSPACE)
		{
			if (pos > 0)
			{
				buffer[--pos] = '\0';
				cout << "\b \b";
			}
		}
		
		else if (ASCII_LOWER_LIM <= input && input <= ASCII_UPPER_LIM)
		{
			if (pos < buffer.size())
			{
				buffer[pos++] = input;
				cout << '*';
			}
		}
	}
	
	cout << endl;
	return 0;
}

void encryptIntoFile(const string &source, const string& login, const SecByteBlock &password)
{
	AutoSeededRandomPool prng;

	SecByteBlock iv(AES::BLOCKSIZE);
	SecByteBlock key(AES::MAX_KEYLENGTH);
		
	prng.GenerateBlock(iv.data(), iv.size());
	prng.GenerateBlock(key.data(), key.size());

	CBC_Mode<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

	SecByteBlock ciphertext(0, password.size());

	ArraySource(password.data(), password.size(), true,
		new StreamTransformationFilter(encryptor, 
			new ArraySink(ciphertext.data(), ciphertext.size())
		)
	);

	ofstream dataFile(dataPath, ios::app | ios::binary);
	if (!dataFile.is_open())
		throw runtime_error("cannot open the data file");

	ofstream keysFile(keysPath, ios::app | ios::binary);
	if (!keysFile.is_open())
		throw runtime_error("cannot open the keys file");

	HexEncoder dataEncoder(new FileSink(dataFile));
	HexEncoder keysEncoder(new FileSink(keysFile));

	dataEncoder.Put((const byte*)&source[0], source.size());
	dataEncoder.MessageEnd();
	dataFile << "|";

	dataEncoder.Put((const byte*)&login[0], login.size());
	dataEncoder.MessageEnd();
	dataFile << "|";

	dataEncoder.Put(ciphertext.data(), ciphertext.size());
	dataEncoder.MessageEnd();
	dataFile << "|";

	dataEncoder.Put(iv.data(), iv.size());
	dataEncoder.MessageEnd();
	dataFile << endl;

	dataFile.close();

	keysEncoder.Put(key.data(), key.size());
	keysEncoder.MessageEnd();
	keysFile << endl;

	keysFile.close();
}

/* ********** REMOVE PROC ********** */
int deleteSource(int lineNum)
{
	fstream keysFile(keysPath, ios::in | ios::out | ios::binary);

	keysFile.seekp((AES::MAX_KEYLENGTH * 2 + 1) * lineNum);

	for (int i = 0; i < 64; i++)
		keysFile << '0';

	keysFile.close();

	return 0;
}

/* _EOF_ */
