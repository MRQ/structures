// microtime.h

/// wickelt den timeval aus der glibc in eine schicke c++-klasse
class MicroTime
{
public:
	class now_t {};
	static now_t now;
	MicroTime(){};
	MicroTime(time_t inp) {data.tv_sec = inp; data.tv_usec = 0; };
	MicroTime(const timeval& inp) : data(inp) {};
	MicroTime(const timespec& inp)
	{data.tv_sec = inp.tv_sec; data.tv_usec = inp.tv_nsec/1000; };
	MicroTime(now_t);
	bool operator < (const MicroTime& rhs) const;
private:
	timeval data;
};
