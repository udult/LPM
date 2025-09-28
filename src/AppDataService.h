/*
 * AppDataService.h - Appdata processing header file
 *
 * LPM 27.09.2025 refined
 */

#ifndef APPDATASERVICE_H
#define APPDATASERVICE_H

/* common includes */
#include <string>
#include <fstream>
#include <conio.h>

using namespace std;
using namespace CryptoPP;

/* userinput char limit */
#define INPUTLIM 32

/* skip characters in stream until delim */
#define CHARSTOSKIP 1000

static const string dataPath = "../vault/data.txt";
static const string keysPath = "../vault/keys.txt";

/* 
 * output available saved sources
 * returns a number of sources loaded (or -1 if file is not available)
 */
int printAvailable();

/* 
 * decryption interface
 * returns a login string decoded
 */
string decryptFromFile(SecByteBlock&, int);

/* read input char by char */
int inputRead(string&);

/* read input sensetive data directly into a secbyteblock */
int secureInputRead(SecByteBlock&);

/* check if entered source exists */
int findSource(const string&);

/* encryption interface */
void encryptIntoFile(const string&, const string&, const SecByteBlock&);

/* set chosen source key into a 00000.... string */
int deleteSource(int);
 
#endif /* APPDATASERVICE_H */