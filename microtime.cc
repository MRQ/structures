#include "libs.h"
#include "microtime.h"

MicroTime::now_t MicroTime::now;

MicroTime::MicroTime(now_t ignore)
{
	gettimeofday(&data, NULL);
};

bool MicroTime::operator < (const MicroTime& rhs) const
{
	if(data.tv_sec < rhs.data.tv_sec) {return true;}
	else if(data.tv_sec > rhs.data.tv_sec) {return false;}
	else if(data.tv_usec < rhs.data.tv_usec) {return true;}
	else {return false;};
};
