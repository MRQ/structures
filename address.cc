// address.cc

#include "libs.h"
#include "address.h"

using namespace std;
using namespace boost;

bool Address::IsIPv4() const
{
	// überprüfen ob innerhalb von 0:0:0:0:0:ffff::/96
	return (
		addr[0] == 0 &&
		addr[1] == 0 &&
		addr[2] == 0 &&
		addr[3] == 0 &&
		addr[4] == 0 &&
		addr[5] == 0xffff
	);
};

std::pair<int64_t, int64_t> Address::ToSql()
{
	int64_t first, second;
	first = (int64_t(addr[0]) << 48)
		+ (int64_t(addr[1]) << 32)
		+ (int64_t(addr[2]) << 16)
		+ int64_t(addr[3]);
	second = (int64_t(addr[4]) << 48)
		+ (int64_t(addr[5]) << 32)
		+ (int64_t(addr[6]) << 16)
		+ int64_t(addr[7]);
	// Die Zahlen werden ins negative Verschoben, damit < und > noch mit
	// signed funktionieren.
	return std::pair<int64_t, int64_t>(
		first -0x8000000000000000,
		second -0x8000000000000000
	);
};

Address Address::FromSql(const int64_t first, const int64_t second)
{
	// in uint umwandeln, damit es keine probleme beim shiften gibt.
	uint64_t first2 = first + 0x8000000000000000;
	uint64_t second2 = second + 0x8000000000000000;
	return From2_64(first2, second2);
};

Address Address::From2_64(const uint64_t first, const uint64_t second)
{
	Address result;
	result.addr[0] = (0xffff000000000000 & first) >> 48;
	result.addr[1] = (0x0000ffff00000000 & first) >> 32;
	result.addr[2] = (0x00000000ffff0000 & first) >> 16;
	result.addr[3] = (0x000000000000ffff & first);
	result.addr[4] = (0xffff000000000000 & second) >> 48;
	result.addr[5] = (0x0000ffff00000000 & second) >> 32;
	result.addr[6] = (0x00000000ffff0000 & second) >> 16;
	result.addr[7] = (0x000000000000ffff & second);
	return result;
};

Address Address::AddMask(int zeros)
{
	if(1 > zeros) zeros = 1;
	if(zeros > 128) zeros = 128;
	uint64_t add1, add2;
	if(zeros <= 64){
		add2 = 0xffffffffffffffff;
		add1 = 0;
		for(int i=64-zeros; i>0; --i) add1 = (add1<<1)|1;
	}
	else{
		add1 = 0;
		add2 = 0;
		for(int i=128-zeros; i>0; --i) add2 = (add2<<1)|1;
	};
	return Address::From2_64(add1, add2);
};

Address::Range Address::Cidr(const std::string& input)
{
	vector<string> split_cidr;
	split(split_cidr, input, is_any_of("/") );
	if(split_cidr.size() < 2){
		// möglicherweise noch einzelne addresse gemeint
		Address single = lexical_cast<Address>(input);
		return Range(single, single);
	};
	Address addr;
	addr = lexical_cast<Address>(split_cidr[0]);
	//cout << ' ' << split_cidr[0] << " = " << addr << endl;
	// netblock-ende bestimmen
	int fixed_bits = lexical_cast<int>(split_cidr[1]);
	if(addr.IsIPv4()) fixed_bits += 96;
	// ^^ nicht ganz sauber, weil ipv6-notation von ipv4-adressen
	// ^^ falsch berücksichtigt wird.
	if(1 > fixed_bits || fixed_bits > 128) throw bad_lexical_cast();
	Address add_addr = Address::AddMask(fixed_bits);
	return Range(addr, addr | add_addr);
};

uint8_t Address::GetByte(int select) const
{
	select &= 0x0f; // absicherung
	uint16_t tmp = addr[select >> 1];
	if(select & 1){
		return tmp & 0xff;
	}
	else {
		return tmp >> 8;
	};
};

Address Address::operator|(const Address& other) const
{
	Address result;
	for(int i=0; i<8; ++i) result.addr[i] = addr[i] | other.addr[i];
	return result;
};

bool Address::operator>(const Address& rhs) const
{
	for(int i=0; i<8; ++i){
		if(addr[i] > rhs.addr[i]){
			return true;
		}
		else if(addr[i] < rhs.addr[i]){
			return false;
		};
	};
	return false; // gleichheit
};
bool Address::operator<(const Address& rhs) const
{
	for(int i=0; i<8; ++i){
		if(addr[i] < rhs.addr[i]){
			return true;
		}
		else if(addr[i] > rhs.addr[i]){
			return false;
		};
	};
	return false; // gleichheit
};


std::ostream& operator<<(std::ostream& lhs, const Address& rhs)
{
	ostream::fmtflags format_backup = lhs.flags();
	if(rhs.IsIPv4()){
		lhs << dec;
		lhs << ((rhs.addr[6] & 0xff00) >> 8);
		lhs << '.';
		lhs << (rhs.addr[6] & 0x00ff);
		lhs << '.';
		lhs << ((rhs.addr[7] & 0xff00) >> 8);
		lhs << '.';
		lhs << (rhs.addr[7] & 0x00ff);
	}
	else{
		// großen bereich mit ansammlung von nullen finden
		int omission_begin = -1;
		int most_zeros = 0;
		int current_zeros = 0;
		for(int i=7; i>=0; --i) if(rhs.addr[i] == 0) {
			++current_zeros;
			if(current_zeros > most_zeros){
				omission_begin = i;
				most_zeros = current_zeros;
			};
		}
		else {
			current_zeros = 0;
		};
		// ausgeben
		lhs << hex << nouppercase;
		for(int i=0; i<8; ++i){
			if(omission_begin == i){
				lhs << (i==0 ? "::":":");
				while(i<7 && rhs.addr[i+1] == 0) ++i;
			}
			else {
				lhs << rhs.addr[i];
				if(i != 7) lhs << ':';
			};
		};
	};
	lhs.flags(format_backup);
	return lhs;
};

/// parst den IPv4-Anhang einer gemischten Adresse oder eine IPv4-Adresse
/// selbst. Helfer-Sub-Funktion.
void Address::IPv4Trailer(std::istream& input, Address& output, bool& success,
	int offset, bool v6trail)
{
	if(offset > 6 || offset < 0) {success = false; return;};
	input >> dec;
	for(int pos=0; pos<4; ++pos){
		if(pos==0 && v6trail) continue;
		int octal = -1;
		input>>octal;
		if(octal == -1 && input.eof()){
			// eigentlich müsste man das nicht berücksichtigen,
			// aber ripes alloclist.txt bugt hier. die benutzen
			// verkürzte Adressen.
			octal = 0;
		};
		if(0 > octal || octal >= 256){success = false; break;};
		if(pos<3 && !input.eof()){
			// trennpunkt los werden
			char dot = 0;
			input>>dot;
			if(dot != '.'){success = false; break;};
		};
		switch(pos){
		case 0: output.addr[offset] = octal << 8; break;
		case 1: output.addr[offset] += octal; break;
		case 2: output.addr[offset +1] = octal << 8; break;
		case 3: output.addr[offset +1] += octal; break;
		};
	};
};

std::istream& operator>>(std::istream& lhs, Address& rhs)
{
	istream::fmtflags format_backup = lhs.flags();
	// Format testen: ipv4, ipv6 oder ungültig
	bool ipv4 = false;
	bool ipv6 = false;
	bool no_number = false;
	/// muss wieder zurückgepusht werden nach dem test
	char putbacks[5];
	char c = 0;
	int cursor = 0;
	for(cursor=0; cursor<5; ++cursor){
		c = 0;
		lhs.get(c);
		putbacks[cursor] = c;
		if(!lhs.good()) break;
		if('0' <= c && c <= '9') {continue;}
		else if('a' <= c && c <= 'f') {ipv6 = true; break; }
		else if(':' == c) {ipv6 = true; break; }
		else if('.' == c) {ipv4 = true; break; }
		else {no_number = true; break;};
	};
	if(cursor == 5) cursor = 4;
	// ^^ bei verlassen der schleife durch überlauf von cursor muss er
	// ^^ zurück in die array gesetzt werden.
	// vv zurückpushen
	for(cursor; cursor >= 0 && lhs.good(); --cursor)
		lhs.putback(putbacks[cursor]);
	// vv noch so ein ripe alloclist.txt-fuckup. normalerweise heißt
	// vv nur eine zahl: dezimale ipv4-adresse, aber hier heißt es:
	// vv class-A-netz.
	if(!no_number && !ipv4 && !ipv6){
		// wir begegnen dem ugly glitch mit einem ugly-hack:
		string v4_glue(putbacks);
		v4_glue += ".0.0.0";
		rhs = lexical_cast<Address>(v4_glue);
		lhs.clear(ios::goodbit);
		lhs.flags(format_backup);
		return lhs; 
	};
	if(ipv4){
		/// tmp ist Ersatz-Addresse. es wird nicht direkt in rhs
		/// geschrieben, weil es bei fail unberührt bleibt.
		Address tmp;
		tmp.addr[0] = 0;
		tmp.addr[1] = 0;
		tmp.addr[2] = 0;
		tmp.addr[3] = 0;
		tmp.addr[4] = 0;
		tmp.addr[5] = 0xffff;
		Address::IPv4Trailer(lhs, tmp, ipv4, 6, false);
		if(ipv4) rhs = tmp;		
	}
	else if(ipv6){
		/// tmp ist Ersatz-Addresse. es wird nicht direkt in rhs
		/// geschrieben, weil es bei fail unberührt bleibt.
		Address tmp;
		// splitter ist das erste uint16, das mit :: aufgefüllt wird.
		int splitter = -1;
		lhs >> hex >> nouppercase;
		int addr_pos = 0;
		for(addr_pos = 0; addr_pos<8; ++addr_pos){
			if(addr_pos > 0){
				// außer bei dem ersten Trenner ":"
				// abfrühstücken
				char sep_char = -1;
				lhs.get(sep_char);
				if(sep_char == '.'){ // dieses beschissene
					// gemischte Format bedienen.
					// bcd-codierung des letzten wertes
					uint16_t& prev = tmp.addr[addr_pos-1];
					unsigned int bcd = prev & 0xf;
					if(bcd > 9) {ipv6 = false; break;};
					bcd += ((prev & 0xf0) >> 4) * 10;
					if(bcd > 99) {ipv6 = false; break;};
					bcd += ((prev & 0xf00) >> 8) * 100;
					if(bcd > 255 || prev & 0xf000)
						{ipv6 = false; break;};
					prev = bcd << 8;
					Address::IPv4Trailer(lhs, tmp, ipv4,
						addr_pos-1, true);
					addr_pos += 1;
					break;
				};
				if(sep_char != ':'){break;};
			}
			/// mit peek prüfen ob "::" kommt.
			char peek = -1;
			lhs.get(peek);
			if(peek == ':'){ // "::" kommt.
				if(splitter != -1){ipv6 = false; break;};
				splitter = addr_pos;
				if(addr_pos == 0){
					// diesmal doch noch ein ':'
					// abfrühstücken
					if(lhs.get() != ':')
						{ipv6 = false; break;};
				};
				
			}
			else if(
				('0' <= peek && peek <= '9') ||
				('a' <= peek && peek <= 'f')
			){ // normale zahl
				lhs.putback(peek);
			}
			else { // fehler oder ende
				if(!lhs.eof()) lhs.putback(peek);
				// hier gehts raus bei abgekürzter Adresse
				break; 
			};
			// uint16 einlesen
			int a_word = -1;
			lhs>>a_word;
			// falscher bereich. kann aber auch heißen: ende.
			if(0 > a_word || a_word > 0xffff){
				if(!lhs.fail()) ipv6 = false;
				break;
			};
			tmp.addr[addr_pos] = a_word;
			
		}; // ende for uint16-schleife
		// die werte ab dem splitter nach rechts schieben.
		if(splitter != -1){
			/// wie weit jeder zu schiebende Wert nach rechts
			/// geschoben werden muss.
			int offset = 8 - addr_pos;
			for(int i=7; i>=splitter; --i){
				int from = i -offset;
				if(from < splitter){
					tmp.addr[i] = 0;
				}
				else {
					tmp.addr[i] = tmp.addr[from];
				};
			};
		}
		else if(addr_pos != 8){ // nicht durchgelaufen ohne splitter
			// ergibt malformat
			ipv6 = false;
		};
		if(ipv6) rhs = tmp;		
	};

	// evtl wird ipv4 oder ivp6 durch den parser wieder gelöscht
	// wenn ein fehler später erkannt wurde.
	if(!ipv4 && !ipv6){
		// fehlerfall
		lhs.clear(ios::failbit);
	}
	else {
		lhs.clear(ios::goodbit);
	};
	lhs.flags(format_backup);
	return lhs;
};

void TestAddress()
{
	cout << "ip-ausgabe\n";
	Address a, b, c, d, e, f, g, h, i;
	cout << a << endl << b << endl << c << endl;
	cout << d << endl << e << endl << f << endl;
	cout << g << endl << h << endl << i << endl;
	cout << "\n\n ip-eingabe";
	const char* test_addr[] = {
		"::1", "::", "2001::", "192.168.0.0",
		"::ffff:8000:0001", "::ffff:127.0.0.1", "::127.0.0.1",
		"::ffff:1.2.3.4", "::1.2.3.4", "1.2.3.4"
		"", "0.0",
		" ::1", "aha", "hoho", "0.0.0.0", "210.1.0.255",
		"2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
		"::1:2:3", "1:2:3::", "1:2:3::7:8",
		":::1:2:3", "1:2:3:::", "1:2:3:::7:8",
		"1:2",
		"3.14",
		"ffff:ffff:ffff:ffff::", "::ffff:ffff:ffff:ffff"
	};
	foreach(const char* addr, test_addr) try{
		cout << "\n“" << addr << "”: ";
		a = lexical_cast<Address>(addr);
		cout << " == " << a;
		std::pair<int64_t, int64_t> sql_pair;
		sql_pair = a.ToSql();
		cout << "\nsql " << sql_pair.first << ", " << sql_pair.second;
		cout << " ";
		cout << Address::FromSql(sql_pair.first, sql_pair.second);
		cout << endl;
		for(int i=0; i<16;++i){
			cout << int(a.GetByte(i)) << ',';
		}
	}
	catch(bad_lexical_cast bad_lex){
		cout << "bad_lex";
	};
	cout << endl;
};

static const long long lowest_ll[] = { 0x0, 0x0};
static const long long highest_ll[] = { 0xffffffffffffffff, 0xffffffffffffffff};

const Address& Address::lowest = *reinterpret_cast<const Address*>(lowest_ll);
const Address& Address::highest = *reinterpret_cast<const Address*>(highest_ll);
