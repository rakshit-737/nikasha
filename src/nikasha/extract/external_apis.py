# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Well-known external API names (SPEC §9.3).

A symbol on these lists belongs to a platform or third-party library, not to the project
under test. It is kept as context but marked ``external``: checks treat it as NEUTRAL and
it never supports a refutation. slopcheck measured third-party APIs as 20% of its false
contradictions (ADR 0003).
"""

from __future__ import annotations

_LIBC = """
abort abs accept access aligned_alloc alloca asctime assert atexit atof atoi atol atoll
bcmp bcopy bind bsearch btowc bzero calloc chdir chmod chown clearerr clock clock_gettime
close closedir connect creat ctime dirname dlclose dlerror dlopen dlsym dprintf dup dup2
endpwent environ epoll_create epoll_ctl epoll_wait errno execl execle execlp execv execve
execvp exit _exit explicit_bzero fchmod fchown fclose fcntl fdopen feof ferror fflush fgetc
fgetpos fgets fileno flock fmemopen fopen fork fprintf fputc fputs fread free freeaddrinfo
freopen fscanf fseek fseeko fsetpos fstat fsync ftell ftello ftruncate fwrite gai_strerror
getaddrinfo getc getchar getcwd getdelim getenv geteuid getgid gethostbyname gethostname
getline getnameinfo getopt getopt_long getpeername getpid getppid getpwnam getpwuid getrlimit
getsockname getsockopt gettimeofday getuid glob gmtime gmtime_r htonl htons inet_addr
inet_ntoa inet_ntop inet_pton ioctl isalnum isalpha isatty isdigit islower isprint ispunct
isspace isupper isxdigit kill labs link listen llabs localtime localtime_r longjmp lseek
lstat malloc malloc_usable_size mblen mbstowcs mbtowc memalign memccpy memchr memcmp memcpy
memmem memmove mempcpy memrchr memset mkdir mkdtemp mkfifo mkstemp mktemp mktime mmap mprotect
munmap nanosleep ntohl ntohs open openat opendir perror pipe poll popen posix_memalign pread
printf pselect ptrace putc putchar putenv puts pwrite qsort raise rand rand_r random read
readdir readlink readv realloc reallocarray realpath recv recvfrom recvmsg remove rename
rewind rmdir sbrk scanf sched_yield select send sendmsg sendto setbuf setenv setjmp setlocale
setrlimit setsockopt setvbuf shutdown sigaction siglongjmp signal sigsetjmp sleep snprintf
socket socketpair sprintf srand srandom sscanf stat stpcpy stpncpy strcasecmp strcat strchr
strcmp strcoll strcpy strcspn strdup strerror strerror_r strftime strlcat strlcpy strlen
strncasecmp strncat strncmp strncpy strndup strnlen strpbrk strptime strrchr strsep strsignal
strspn strstr strtod strtof strtoimax strtok strtok_r strtol strtold strtoll strtoul strtoull
strtoumax strxfrm symlink sync syscall sysconf system tcgetattr tcsetattr time timegm tmpfile
tmpnam tolower toupper truncate umask uname ungetc unlink unsetenv usleep utime utimes
va_arg va_copy va_end va_start valloc vasprintf asprintf vfprintf vprintf vsnprintf vsprintf
wait waitpid wcscat wcschr wcscmp wcscpy wcslen wcsncpy wcstombs wctomb wmemcpy wmemset write
writev
"""

_PTHREAD = """
pthread_attr_destroy pthread_attr_init pthread_attr_setstacksize pthread_cancel
pthread_cond_broadcast pthread_cond_destroy pthread_cond_init pthread_cond_signal
pthread_cond_timedwait pthread_cond_wait pthread_create pthread_detach pthread_equal
pthread_exit pthread_getspecific pthread_join pthread_key_create pthread_key_delete
pthread_kill pthread_mutex_destroy pthread_mutex_init pthread_mutex_lock
pthread_mutex_trylock pthread_mutex_unlock pthread_once pthread_rwlock_rdlock
pthread_rwlock_unlock pthread_rwlock_wrlock pthread_self pthread_setspecific
pthread_sigmask pthread_spin_lock pthread_spin_unlock
"""

_WIN32 = """
CloseHandle CreateFileA CreateFileW CreateProcessA CreateProcessW CreateThread
DeleteCriticalSection EnterCriticalSection GetLastError GetModuleHandleA GetModuleHandleW
GetProcAddress GetProcessHeap HeapAlloc HeapFree HeapReAlloc InitializeCriticalSection
LeaveCriticalSection LoadLibraryA LoadLibraryW LocalAlloc LocalFree MultiByteToWideChar
ReadFile SetLastError Sleep VirtualAlloc VirtualFree VirtualProtect WaitForSingleObject
WideCharToMultiByte WriteFile lstrcpyA lstrcpyW lstrlenA lstrlenW RtlCopyMemory
RtlZeroMemory SecureZeroMemory memcpy_s strcpy_s strcat_s sprintf_s _snprintf _stricmp
"""

_OPENSSL = """
BIO_free BIO_new BIO_read BIO_write BN_bin2bn BN_free BN_new CRYPTO_free CRYPTO_malloc
ERR_get_error ERR_error_string EVP_CIPHER_CTX_free EVP_CIPHER_CTX_new EVP_DecryptFinal_ex
EVP_DecryptInit_ex EVP_DecryptUpdate EVP_DigestFinal_ex EVP_DigestInit_ex EVP_DigestUpdate
EVP_EncryptFinal_ex EVP_EncryptInit_ex EVP_EncryptUpdate EVP_MD_CTX_free EVP_MD_CTX_new
EVP_PKEY_free OPENSSL_free OPENSSL_malloc OPENSSL_cleanse OPENSSL_init_ssl PEM_read_bio_X509
RAND_bytes SSL_CTX_free SSL_CTX_new SSL_accept SSL_connect SSL_free SSL_get_error SSL_new
SSL_read SSL_set_fd SSL_shutdown SSL_write X509_free X509_get_subject_name X509_verify_cert
d2i_X509 i2d_X509 SHA256 MD5 HMAC
"""

_ZLIB = """
adler32 compress compress2 compressBound crc32 deflate deflateEnd deflateInit deflateInit2
deflateReset gzclose gzopen gzread gzwrite inflate inflateEnd inflateInit inflateInit2
inflateReset uncompress uncompress2 zlibVersion
"""

_CXX = """
std::abort std::array std::basic_string std::copy std::cout std::cerr std::endl std::fill
std::make_shared std::make_unique std::map std::memcpy std::move std::shared_ptr std::sort
std::string std::string_view std::terminate std::thread std::unique_ptr std::unordered_map
std::vector std::vector::at std::vector::operator[] std::vector::push_back
std::basic_string::append std::basic_string::substr operator new operator delete
__cxa_throw __cxa_allocate_exception __cxa_begin_catch __cxa_end_catch
"""

_COMPILER = """
__builtin_memcpy __builtin_memset __builtin_expect __builtin_unreachable __builtin_trap
__builtin_object_size __builtin___memcpy_chk __memcpy_chk __strcpy_chk __sprintf_chk
__stack_chk_fail __assert_fail __errno_location
"""


def _words(*blocks: str) -> frozenset[str]:
    return frozenset(w for block in blocks for w in block.split())


#: Every external name, exactly as it would be written in code.
EXTERNAL_APIS: frozenset[str] = _words(_LIBC, _PTHREAD, _WIN32, _OPENSSL, _ZLIB, _CXX, _COMPILER)


def is_external(name: str) -> bool:
    """Return whether ``name`` (optionally qualified, e.g. ``std::memcpy``) is external."""
    if name in EXTERNAL_APIS:
        return True
    bare = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    return name.startswith("std::") or bare in EXTERNAL_APIS
