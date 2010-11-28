
#include <libs.h>
#include <errno-exception.h>

ErrnoException::ErrnoException(int number_)
{
	if(number_) number = number_;
	else number = errno;
};

const char* ErrnoException::what() const throw()
{
	return strerror(number);
};