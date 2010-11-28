// address.h

/// IP-Adressen
class Address
{
public:
	// -- Typen --
	/// es wird einfach so oft gebraucht,
	/// deshalb definiert ich das jetzt mal:
	typedef std::pair<Address, Address> Range;
	// -- Funktionen --
	bool IsIPv4() const;
	/// Wandelt in ein Format um,
	/// dass leichter in SQL gespeichert werden kann.
	std::pair<int64_t, int64_t> ToSql();
	/// Aus dem SQL-Format zurück zu Address.
	static Address FromSql(const int64_t first, const int64_t second);
	/// aus zwei 64bit-uints erzeugen.
	static Address From2_64(const uint64_t first, const uint64_t second);
	/// erzeugt eine Address mit der angegebenen anzahl nullen.
	/// inverse der Netmask.
	static Address AddMask(int zeros);
	/// erzeugt aus einer cidr-notation die niedrigste und höchste
	/// Adresse.
	static Range Cidr(const std::string& input);
	/// gibt ein einzelne Byte zurück, most significant = 0
	uint8_t GetByte(int select) const;

	Address operator|(const Address& other) const;
	friend std::ostream& operator<<(std::ostream&, const Address&);
	friend std::istream& operator>>(std::istream&, Address&);
	bool operator>(const Address& rhs) const;
	bool operator<(const Address& rhs) const;

	static const Address& lowest;
	static const Address& highest;
private:
	static void IPv4Trailer(std::istream&, Address&, bool&, int, bool);
	uint16_t addr[8]; // ipv6-format
};

std::ostream& operator<<(std::ostream&, const Address&);
std::istream& operator>>(std::istream&, Address&);

// Testcode für Address-IO. Ohne automatische Kontrolle.
void TestAddress();

