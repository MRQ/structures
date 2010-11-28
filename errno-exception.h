// errno-exception.h

class ErrnoException : public std::exception
{
public:
	ErrnoException(int number_ = 0);
	virtual const char* what() const throw();
private:
	int number; ///< errno-number at throw-time
};