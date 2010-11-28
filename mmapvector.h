// mmapvector.h

/// versucht das Verhalten von std::vector nachzubilden, basiert aber auf
/// einer mmap, so dass Daten in einer Datei liegen.

template <typename T>
class mmapvector
{
public:
	// -- typedefs --
	typedef T value_type;
	typedef T* pointer;
	typedef T& reference;
	typedef const T& const_reference;
	typedef size_t size_type;
	typedef ssize_t difference_type;
	// vorerst keine interatoren
	// -- allocation --
	mmapvector(const std::string& location);
	~mmapvector();
	void reserve(size_type new_reserved);
	size_type capacity() const;
	size_type max_size() const;
	size_type size() const;
	bool empty() const;
	void clear();
	// -- operationen ohne iteratoren --
	reference operator[](size_type n);
	void push_back(const T&);
private:
	struct Header
	{
		uint32_t reserved; ///< wie groß ist die datei?
		uint32_t size; ///< wie viele einträge gibt es wirklich?
	};
	Header* begin;
	size_t mmap_size;
	T* array;
	long descriptor; ///< file descriptor.
	const uint32_t min_reserve;
	///< wird so hoch gesetzt, es gerade eine page belegt, aber mindestens
	///< 4 elemente
	static uint32_t InitMinReserve();
};

template <typename T>
mmapvector<T>::mmapvector(const std::string& location)
	: begin(NULL), array(NULL), min_reserve(InitMinReserve())
{
	descriptor = open(
		location.c_str(),
		O_RDWR | O_CREAT,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
	);
	if(descriptor == -1) throw ErrnoException();
	Header init_header;
	int bytes_read = TEMP_FAILURE_RETRY(
		read(descriptor, &init_header, sizeof(Header))
	);
	if(bytes_read == 0){ // malformat oder leer.
		// -- header vorbereiten --
		init_header.reserved = min_reserve;
		init_header.size = 0;
		// -- header schreiben --
		lseek(descriptor, 0, SEEK_SET);
		TEMP_FAILURE_RETRY(
			write(descriptor, &init_header, sizeof(Header))
		);
	};
	reserve(init_header.reserved);
};

template <typename T>
uint32_t mmapvector<T>::InitMinReserve()
{
	uint32_t result;
	ssize_t pagesize = sysconf (_SC_PAGESIZE);
	if(pagesize == -1) throw ErrnoException();
	result = (pagesize - sizeof(Header) -3) / sizeof(T);
	// ^^ -3 wegen EOF-string;
	if(result < 4) result = 4;
	return result;
};


template <typename T>
void mmapvector<T>::reserve(mmapvector<T>::size_type new_reserved)
{
	if(new_reserved < min_reserve) new_reserved = min_reserve;
	if(begin){
		if(new_reserved < begin->size) new_reserved = begin->size;
		munmap(begin, mmap_size);
		array = 0;
		// begin wird absichtlich nicht =0 gesetzt, weil wir versuchen
		// den gleichen speicherbereich nochmal zu bekommen.
	};
	mmap_size = sizeof(Header) + sizeof(T) * new_reserved;
	if(ftruncate(descriptor, mmap_size +3)) throw ErrnoException ();
	// ^^ +3 wegen eof-string
	lseek(descriptor, mmap_size, SEEK_SET);
	TEMP_FAILURE_RETRY(
		write(descriptor, "EOF", 3)
	);
	begin = (Header*)mmap(
		begin, // gewünschte adresse
		mmap_size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		descriptor,
		0 // offset
	);
	if((long long)(begin) == -1) throw ErrnoException();
	array = reinterpret_cast<T*>( &(begin[1]) );
	begin->reserved = new_reserved;
};

template <typename T>
size_t mmapvector<T>::capacity() const
	{return begin->reserved;};

template <typename T>
size_t mmapvector<T>::max_size() const
	{return 0xffffffffu;};

template <typename T>
size_t mmapvector<T>::size() const
	{return begin->size;};

template <typename T>
bool mmapvector<T>::empty() const
	{return !(begin->size);};

template <typename T>
void mmapvector<T>::clear()
{
	begin->size = 0;
	reserve(0);
};

template <typename T>
mmapvector<T>::~mmapvector()
{
	if(begin) munmap(begin, mmap_size);
	close(descriptor);
};

template <typename T>
T& mmapvector<T>::operator[](mmapvector<T>::size_type n)
{
	if(n+1 > begin->reserved){
		int new_reserve = (n+1) + ((n+1) >> 1);
		reserve(new_reserve);
		// also etwa das 1,5-fache, nicht ganz das 2-fache, wie im
		// original-vector;
	};
	if(n+1 > begin->size){
		begin->size = n+1;
	};
	return array[n];
};

template <typename T>
void mmapvector<T>::push_back(const T& input)
{
	(*this)[size()] = input;
};