
/*
project(RSA)
*/

#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include <assert.h>
#include <map>
#include <sstream>
#include <string>
#include <iomanip>

//using std::cout;
//using std::endl;
//using std::pair;
//using std::map;
//using std::make_pair;
//using std::string;

using namespace std;

using keyset = map<string, pair<mpz_class, mpz_class>>;

//reads a txt file and returns the text inside
string readFile(string fileName){
    string fileText;
    string line;
    std::ifstream myfile (fileName);
    if (myfile.is_open()){
        while ( getline (myfile,line) ){
            fileText += line + "\n";
        }
        myfile.close();
    }
    else cout << "Unable to open file";

    return fileText;
}

//outputs a string to a txt file
void writeFile(string text, string fileName){
    std::ofstream myfile (fileName);
    if (myfile.is_open()){
        myfile << text;
        myfile.close();
        }
    else cout << "Unable to open file";

}


// Calculation of the RSA keyset using GMP
// https://gmplib.org/
keyset rsa_keys(const mpz_t p, const mpz_t q, const mpz_t e) {
    mpz_t d, lambda, gcd;
    mpz_inits(d, lambda, gcd, NULL);
    /*GMP:Initialize a NULL-terminated list of mpz_t variables, and set their values to 0.*/
    
    // 1-Choose two distinct prime numbers p and q.
    mpz_class pc{p}; //p : a prime number (distinct, secret)
    mpz_class qc{q}; //q : another prime number (distinct, secret)
    /*GMP:Construct an mpz_class from an mpz_t. The value in "p" or "q" is copied into the 
    new mpz_class (pc & qc), there won’t be any permanent association between it and "p" or "q".*/
    
    // 2-Compute n = p * q (n:modulus for both the public and private keys)
    mpz_class nc = pc * qc;// n = p * q 
    
    /* 3-Compute λ(n), where λ is Carmichael's totient function. 
    Since n = pq, λ(n) = lcm(λ(p),λ(q)), and since p and q are prime,
    λ(p) = φ(p) = p − 1 and likewise λ(q) = q − 1.
    Hence λ(n) = lcm(p − 1, q − 1). λ(n) is kept secret. */
    mpz_class pc_1 = pc - 1; // p-1
    mpz_class qc_1 = qc - 1; // q-1
    mpz_lcm(lambda, pc_1.get_mpz_t(), qc_1.get_mpz_t());
    /*Set lambda to the least common multiple of op1 and op2. lambda is always
     positive, irrespective of the signs of op1 and op2. lambda will be zero 
     if either op1 or op2 is zero.*/
    mpz_class lambdac{lambda};
    cout << "lambda = " << lambdac << endl;

    /* 4-Choose an integer e such that 1 < e < λ(n) and 
    gcd(e, λ(n)) = 1; that is, e and λ(n) are coprime.*/
    // e must be bigger than 1
    mpz_class ec{e};
    assert(ec > 1);
    // e must be smaller than lambda
    assert(ec < lambdac);
    // GCD(e, lambda) must be 1
    mpz_gcd(gcd, e, lambda);
    /*GMP:Set gcd to the greatest common divisor of e and lambda. The result is 
     always positive even if one or both input operands are negative. Except if
     both inputs are zero; then this function defines gcd(0,0) = 0. */
    mpz_class gcdc{gcd};
    assert(gcdc == 1);
    
    /* 5-Determine d as d ≡ e−1 (mod λ(n)); that is, d is the modular 
    multiplicative inverse of e modulo λ(n).This means: solve for d 
    the equation d⋅e ≡ 1 (mod λ(n)). d can be computed efficiently by 
    using the Extended Euclidean algorithm. */
    mpz_invert(d, e, lambda);
    /* GMP:Compute the inverse of e modulo lambda and put the result in d. If 
    the inverse exists, the return value is non-zero and d will satisfy 
    0 <= d < abs(lambda) (with d = 0 possible only when abs(lambda) = 1. 
    If an inverse doesn’t exist the return value is zero and d is undefined.
     The behaviour of this function is undefined when lambda is zero.
    */
    mpz_class dc{d};
    // e * d MOD lambda must be 1
    mpz_class calc = ec * dc % lambdac;
    assert(calc == 1);

    /*The public key consists of the modulus n and the public (or encryption)
     exponent e. The private key consists of the private (or decryption) 
     exponent d, which must be kept secret. */
    keyset result{{"public",  make_pair(ec, nc)},//public_key(e, n)
                  {"private", make_pair(dc, nc)}};//private_key(d, n./)

    mpz_clears(d, gcd, lambda, NULL);
    //GMP:Free the space occupied by a NULL-terminated list of mpz_t variables.

    return result;
}


//Convert String to Number 
 std::string convert_to_number(const std::string &plaintext)
{
    std::stringstream ss;
    for (auto c: plaintext)
    {
        ss << std::setfill('0') << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}
//Convert Number to String
std::string convert_to_string(const std::string &number)
{
    std::stringstream ss;
    for (unsigned i = 0; i < number.length(); i += 2) {
        ss << static_cast<char>(std::stoi(number.substr(i, 2)));
    }
    return ss.str();
}


// RSA encryption
mpz_class encrypt(const mpz_t message, //plaintext
                  const mpz_t e,       //public key (e, n)
                  const mpz_t n) {
    mpz_t encrypted;
    mpz_init(encrypted);
    mpz_powm(encrypted, message, e, n);
    //GMP:void mpz_powm(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod) --- Set rop to (base raised to exp) modulo mod.
    mpz_class result{encrypted};
    mpz_clear(encrypted);

    return result;
}

// RSA decryption
mpz_class decrypt(const mpz_t encrypted, //ciphertext
                  const mpz_t d,         //private key(d, n)
                  const mpz_t n) {
    mpz_t original;
    mpz_init(original);
    mpz_powm(original, encrypted, d, n);
    //GMP:void mpz_powm(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod) --- Set rop to (base raised to exp) modulo mod.
    mpz_class result{original};
    mpz_clear(original);

    return result;
}

void display(mpz_class message, keyset k, char* flag, string outfile) {
    mpz_class e = k["public"].first;
    mpz_class d = k["private"].first;
    mpz_class n = k["public"].second; 

    if(flag[0] == 'e'){
        mpz_class encrypted = encrypt(message.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
        writeFile(encrypted.get_str(), outfile);
        cout << "Encrypted message = " << encrypted << endl;
    }
    else if(flag[0] == 'd'){
        mpz_class decrypted = decrypt(message.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
        writeFile(convert_to_string(decrypted.get_str()), outfile);
        cout << "Decrypted message = " << decrypted << endl;
        cout << "Decrypted message as string = " << convert_to_string(decrypted.get_str()) << endl;
    }

    cout << endl;
}

//Function Template: We write a generic function that can be used for different data types.(for ex: int msg, char msg , etc.)
template<typename T>
void display(T msg, T pi , T qi , T ei, char* flag, string outfile) 
{

    cout << "Initializing with p = " << pi << ", q = " << qi << ", e = " << ei << endl;

    mpz_t n, d;
    mpz_inits(n, d, NULL);//Initialize a NULL-terminated list of mpz_t variables, and set their values to 0.

    mpz_class p{pi};//The value in "T pi" is copied into the new mpz_class p
    mpz_class q{qi};//The value in "T qi" is copied into the new mpz_class q
    mpz_class e{ei};//The value in "T ei" is copied into the new mpz_class e
    mpz_class original{msg};//The value in "T msg" is copied into the new mpz_class original

    auto k = rsa_keys(p.get_mpz_t(), q.get_mpz_t(), e.get_mpz_t());
    display(original, k, flag, outfile);
    mpz_clears(n, d, NULL);
}
 
int main(int argc, char **argv) { 
    //checks if there are the propper number of flags
    if(argc == 2){
        std::cerr << "No Flag Given!" << endl;
        return 1;
    }

    //sets flag equal to the first flag given
    char* flag = argv[1];
    string outfile = argv[3];

    //checks if the flags are useable
    if(flag[0] != 'e' && flag[0] != 'd'){
        std::cerr << "Inpropper Flag Given!" << endl;
        return 1;
    }

    string message = readFile(argv[2]);

    //convert input to number so it can be encrypted
    if(flag[0] == 'e'){
        message = convert_to_number(message);
    }
    
    cout << "message as number = " << message << endl;

    display(message.c_str(),
            "4140882337963353260132968912797093926696606715205916930968650073419967500708843383081228316891231422343972754152595512300455625695656340112031976778504913",
            "6765712371914185734508412533619386523778830860023689812152561681271034626938604740703777816784147507058936013039127750525290802329248710165227533140888029",
            "65537", flag, outfile);
    
    return 0;
}


//This File also have a MakeFile
//TO MAKE THIS FILE     :make
//TO UN AFTER CREATION :./main.exe
//------------or-----------------
//TO MAKE THIS FILE     : g++ main.cpp -lgmpxx -lgmp
//TO RUN AFTER CREATION : ./a.out
