#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <dlfcn.h> 
// dlopen dlclose
#include <sys/mman.h> 
// mmprotect
#include <unistd.h> 
// _SC_PAGE_SIZE
#include <string.h>
#include <sys/socket.h>
//getaddrinfo
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h> // bool
#include <elf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
// getaddrinfo
#include <sys/stat.h>

static int this_fd = -1;

// struct black_list{
//     //存取config
//     char* black_line;
//     struct black_list* next;
// };

// typedef struct black_list* blaptr;

// static blaptr open_black = NULL;
// static blaptr connect_black = NULL;
// static blaptr getaddrinfo_black = NULL;
const char *global_node;
// static char* read_black = NULL;
// static blaptr read_black_this;
// static int read_black_len =0 ;

extern int errno;
//########################## fake_func##############################
// bool ckeck_black( blaptr head, const char *name) {
//     blaptr temp = head;
//     while( temp != NULL ) {
//         if( strcmp(temp->black_line, name) == 0 )
//             return true;
//         temp = temp->next;    
//     } // while
//     return false;
// } // ckeck_black

static char* filter = NULL;  


bool check_black_in_line( const char *name, ssize_t len , char* read_black ) {
    if( strstr( name, read_black ) != NULL){
        return true;
    } // if
    int read_black_len  = strlen(read_black);

    ssize_t old_filter_len = 0;
    char check[2*read_black_len-1];

    if ( filter != NULL ) {
        old_filter_len = strlen(filter);
        memcpy( check, filter, old_filter_len );
    }

    if( len > (read_black_len -1 ) ) {
        int num_chars_to_keep = read_black_len-1;
        for( int i =0; i < num_chars_to_keep; i++)
            check[old_filter_len+i] =  name[i];
    } // if

    if( strstr( check, read_black ) != NULL){
        return true;
    } // if

    size_t buf_size = strlen;


    
    if( len <= (read_black_len -1 ) && len != 0 ) {
        filter = malloc( len+1);        
        for( int i = 0; i < len; i++ )
            filter[i] = name[i];
    } // if
    else {
        filter = malloc( read_black_len);
        int num_chars_to_keep = read_black_len-1;
        int start = len - num_chars_to_keep;
        for( int i =0; i < num_chars_to_keep; i++)
            filter[i] =  name[start+i];
    } // if

    // printf("start  %s   end\n", filter);

    return false;
} // check_black_in_line()

bool blacklist_open(const char* name){
    // const char* op
    struct stat buf;
    char resolved_path[128];
    bool begin = false;
    FILE *file = fopen(getenv("SANDBOX_CONFIG"),"r");
    ssize_t read;
    char *line = NULL;
    size_t len = 0;    
    char* ch = NULL;
    // file is a link
    while ((read = getline(&line, &len, file) != -1 ) ) {
        if (strstr(line, "BEGIN") != NULL && strstr(line, "open") != NULL) {
            begin = true;
        }
        else if( begin && strstr(line, "open") != NULL && strstr(line, "END") != NULL ) {
            return false;
        } // if
        else if(begin){
            if( ch = strstr(line, "\n") ) {
                *ch = '\0';
            } // if
            char realfilepath[1024] = "";
            realpath(line, realfilepath);

            if(strstr(name, realfilepath) != NULL){
                return true;
            } // if

        } // else
    } // while
    free(line);

    return false;
} // 

int fake_open(const char *name, int flags, ...) {

    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    int (*old_open)(const char *, int, ...) = NULL;
    old_open = dlsym(handle, "open");
    dlclose(handle);
    va_list args;
    mode_t mode = 0;

    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);
    int old_return;
    char realfilepath[1024] = "";
    realpath(name, realfilepath);
    // Check if the file is blacklisted
    if (blacklist_open(name)){
        errno = EACCES;
        dprintf(this_fd, "[logger] open(\"%s\", %d, %d) = %d\n", name, flags, mode,-1);
        return -1;
    }

    if (mode == 0)
        old_return = old_open(name, flags);
    else
        old_return = old_open(name, flags, mode);


    if( old_return != -1)
        filter = NULL;


    dprintf(this_fd, "[logger] open(\"%s\", %d, %d) = %d\n", name, flags, mode, old_return);

    return old_return;
} // fake_open

bool blacklist_read(void *content, ssize_t read_len) {
    bool begin = false;
    FILE *fp = fopen(getenv("SANDBOX_CONFIG"),"r");
    ssize_t read;
    char *line = NULL;
    size_t len = 0;    
    char* ch = NULL;
    while ((read = getline(&line, &len, fp) != -1 ) ) {
        if (strstr(line, "BEGIN") != NULL && strstr(line, "read") != NULL) {
            begin = true;
        }
        else if (strstr(line, "END") != NULL && strstr(line, "read") != NULL) {
            return false;
        }
        else if (begin) {
            if( ch = strstr(line, "\n") ) {
                *ch = '\0';
            } // if

            // if(check_black_in_line(content , read_len , line)){
            //     return true;
            // }
            if(strstr(content , line)){
                return true;
            }            
        }
    }
    return false;
}

ssize_t fake_read( int fd, void *buf, size_t len ) {
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    ssize_t (*old_read)(int ,void*,size_t) = NULL;
    old_read= dlsym(handle, "read");
    dlclose(handle);
    ssize_t old_return;
    // old_return = old_read( fd, buf , len);

    FILE *file;
    char filename[30] = "";
    sprintf(filename, "%d-%d-read.log", getpid(), fd);
    file = fopen(filename, "a");
    old_return = old_read( fd, buf , len);
    if (blacklist_read(buf, old_return)) {
        close(fd);
        errno = EIO;
        dprintf(this_fd,  "[logger] read(%d, %p, %ld) = -1\n", fd, buf, len);
        return -1;
    }

    fwrite( buf, sizeof(char), old_return,file);

    dprintf(this_fd,  "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, len, old_return);
    // //write log into pid-fd-read.log
    fclose(file);
    return old_return;
} // fake_read


ssize_t fake_write( int fd, const void *buf, size_t count) {
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    ssize_t (*old_write)(int ,const void*,size_t) = NULL;
    old_write = dlsym(handle, "write");
    dlclose(handle);
    ssize_t old_return;
    FILE *file;
    char filename[128] = "";
    sprintf(filename, "%ld-%d-write.log", (long)getpid(), fd);
    file = fopen(filename, "a");
    old_return = old_write(fd ,buf, count);
    dprintf(this_fd,  "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, old_return);
    //write log into pid-fd-write.log  
    fwrite( buf,sizeof(char), old_return,file);
    fclose(file);

    return old_return;
} // fake_write

bool blacklist_connect(const char *name){

    char cat_port[8];
    bool begin = false;
    FILE *file = fopen(getenv("SANDBOX_CONFIG"),"r");
    ssize_t read;
    char *line = NULL;
    size_t len = 0; 
    while ((read = getline(&line, &len, file) != -1 ) ) {
        if (strstr(line, "BEGIN") != NULL && strstr(line, "connect") != NULL) {
            begin = true;
        }
        else if (strstr(line, "END") != NULL && strstr(line, "connect") != NULL) {
            return false;
        }
        else if (begin) {
            if(strstr(line, name)){
                return true;
            }
        }
    }
    return false;
} // blacklist_connect()

int fake_connect(int sockfd, const struct sockaddr_in *addr, socklen_t addrlen) {
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    int (*old_connect)(int, const struct sockaddr_in *,socklen_t ) = NULL;
    old_connect= dlsym(handle, "connect");
    dlclose(handle);
    int port = ntohs(addr->sin_port);
    char ip[INET_ADDRSTRLEN];
    inet_ntop( addr->sin_family, &addr->sin_addr, ip, sizeof(ip));
    int old_return;
    char name[128] = "";
    snprintf(name, 128, "%s:%d", global_node, port);  

    if(blacklist_connect(name)){
        errno = ECONNREFUSED;
        dprintf(this_fd,  "[logger] connect(%d,\"%s\", %d) = -1\n", sockfd, ip, addrlen);
        return -1;
    } // if
    old_return = old_connect(sockfd , addr, addrlen);
    dprintf(this_fd,  "[logger] connect(%d,\"%s\", %d) = %ld\n", sockfd, ip, addrlen, old_return);
    return old_return;
} // fake_connect

bool blacklist_getaddrinfo(const char *name){

    bool begin = 0;
    FILE *file = fopen(getenv("SANDBOX_CONFIG"),"r");
    ssize_t read;
    char *line = NULL;
    size_t len = 0; 
    while ((read = getline(&line, &len, file) != -1 ) ) {
        if (strstr(line, "BEGIN") != NULL && strstr(line, "getaddrinfo") != NULL) {
            begin = true;
        } // if
        else if (strstr(line, "END") != NULL && strstr(line, "getaddrinfo") != NULL) {
            return false; 
        } // else if
        else if(strstr(line, name) && begin ){
            return true;
        } // else if
    } // while
    return false;
} // blacklist_getaddrinfo

int fake_getaddrinfo(const char *restrict node, const char *restrict service, 
                    const struct addrinfo *restrict hints,
                    struct addrinfo **restrict res) {
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    int (*old_getaddrinfo)(const char *restrict, const char *restrict,
                                const struct addrinfo *restrict, struct addrinfo **restrict) = NULL;
    old_getaddrinfo = dlsym(handle, "getaddrinfo");
    dlclose(handle);
    int old_return;
    global_node = node;
    if(blacklist_getaddrinfo(node)){
        dprintf(this_fd,  "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %ld\n", node, service, hints, res, EAI_NONAME);
        return EAI_NONAME;
    }
    old_return = old_getaddrinfo( node, service, hints, res);


    dprintf(this_fd,  "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %ld\n", node, service, hints, res,old_return);
    return old_return;

} // fake_getaddrinfo

int fake_system(const char *command) {
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    int (*old_system)(const char *) = NULL;
    old_system = dlsym(handle, "system");
    dlclose(handle);
    if (command == NULL) {
        return 1;
    }
    dprintf(this_fd,  "[logger] system(\"%s\")\n", command);
    old_system(command);
    return 0;

} // fake_system

//####################  config  #############################
// blaptr readconfig( FILE *file ) {
//     ssize_t read;
//     char *line = NULL;
//     size_t len = 0;    
//     char* ch = NULL;
//     blaptr temp = NULL;
//     blaptr head = NULL;
//     blaptr prev = NULL;
//     while ((read = getline(&line, &len, file) != -1 ) ) {
//         if(  strstr(line, "END") != NULL ) {
//             return head;
//         } // if
//         if( ch = strstr(line, "\n") ) {
//             *ch = '\0';
//         } // if

//         temp = malloc(sizeof(struct black_list));
//         temp->black_line = malloc(sizeof(line ));
//         strcpy( temp->black_line,line ); 
        
//         if(head == NULL) 
//             head = temp;
//         else
//             prev->next = temp;
//         prev = temp;
//         temp = temp->next;
//     } // while
//     free(line);
//     return head;
// } // readconfig



// blaptr readconfig_open( FILE *file ) {
//     ssize_t read;
//     char *line = NULL;
//     size_t len = 0;    
//     char* ch = NULL;
//     blaptr temp = NULL;
//     blaptr head = NULL;
//     blaptr prev = NULL;
//     while ((read = getline(&line, &len, file) != -1 ) ) {
//         if(  strstr(line, "END") != NULL ) {
//             return head;
//         } // if
//         if( ch = strstr(line, "\n") ) {
//             *ch = '\0';
//         } // if

//         temp = malloc(sizeof(struct black_list));
//         char realfilepath[1024] = "";
//         realpath(line, realfilepath);
//         temp->black_line = malloc(sizeof( realfilepath ));
//         strcpy( temp->black_line, realfilepath ); 
        
//         if(head == NULL) 
//             head = temp;
//         else
//             prev->next = temp;
//         prev = temp;
//         temp = temp->next;
//     } // while
//     free(line);
//     return head;
// } // readconfig

//####################config#############################
// void got_func( char* filename, long base ) {
//     pid_t pid;
//     int pipefd[2];
//     // char cmd[1024] = "";
//     // snprintf(cmd, 1024, "readelf -r %s | grep %s@\n", filename, func_name );
//     // test-1 pipe fork
//     char *env[] = { NULL };
//     if (pipe(pipefd) < 0) {
//         perror("pipe");
//         exit(EXIT_FAILURE);
//     } // if 
//     pid = fork();
//     if (pid == -1) {
//         return -1;
//     } // if 
//     else if (pid == 0) {
//         close(pipefd[0]); // 關閉管道讀端
//         dup2(pipefd[1], STDOUT_FILENO); // 將 stdout 重定向到管道寫端
//         char *command = "/usr/bin/readelf";
//         char *args[] = { "readelf", "-r", filename, NULL };
//         execle(command, args[0], args[1], args[2], NULL, env);
//         perror("execle");
//         exit(1);
//     } // else if
//     else {
//         // waitpid( pid,NULL, 0);
//         close(pipefd[1]); // 關閉管道寫端
//         FILE *fp = fdopen(pipefd[0], "r");
//         char *line = NULL;
//         size_t len = 0;
//         ssize_t nread;
//         while ((nread = getline(&line, &len, fp) != -1 ) ) {
//             long addr;
//             char symbol_addend[64];
//             char* symbol;
//             sscanf(line, "%lx  %*s %*s %*s %s@", &addr, symbol_addend);
//             symbol = strtok(symbol_addend, "@");
//             long func_addr;
//             if( symbol == NULL )
//                 continue;
//             else if( strcmp(symbol,"open") == 0 ) {
//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_open );
//                 // printf("%s\n", line);
//             } // else if
//             else if( strcmp(symbol,"read") == 0 ) {
//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_read );

//                 // printf("%s\n", line);
//             } // else if
//             else if( strcmp(symbol,"write") == 0) {

//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_write );
//                 // printf("%s\n", line);
//             } // else if
//             else if( strcmp(symbol,"connect") == 0 ){

//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_connect );

//                 // printf("%s\n", line);
//             } // else if
//             else if( strcmp(symbol,"getaddrinfo") == 0 ){

//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_getaddrinfo );

//                 // printf("%s\n", line);
//             } // else if
//             else if( strcmp(symbol,"system") == 0){
//                 func_addr = base + addr;
//                 hijack_got( func_addr, fake_system );

//                 // printf("%s\n", line);
//             } // else if
//         } // while

//         free(line);
//         fclose(fp);
//         close(pipefd[0]);

//     } // else
//     // char cmd[1024] = "";
//     // snprintf(cmd, 1024, "readelf -r %s | grep %s@ > elf.txt", filename, func_name);
//     // fake_system("touch elf.txt");
//     // fake_system(cmd);
//     // fake_system("rm -f elf.txt");
//     return 0;

// } // got_func()

void got_func( char* filename, long base ) {
    //https://stackoverflow.com/questions/70583281/print-the-names-of-the-sections-headers-of-an-elf-file
    FILE *fp;
    // /proc/self/exe
    fp = fopen(filename, "rb");
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    fread(&elfHdr, sizeof(elfHdr), 1, fp);

    // find section name
    fseek(fp, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
    fread(&sectHdr, sizeof(sectHdr), 1, fp);
    char *SectNames;
    SectNames = malloc(sectHdr.sh_size);
    fseek(fp, sectHdr.sh_offset, SEEK_SET);
    fread(SectNames, sectHdr.sh_size, 1, fp);
    // read all section headers, find .rela.plt
    int rela_idx;
    int dynsym_idx;
    for (int idx = 0; idx < elfHdr.e_shnum; idx++)
    {
        const char *name = "";

        fseek(fp, elfHdr.e_shoff + idx * sizeof(sectHdr), SEEK_SET);
        fread(&sectHdr, sizeof(sectHdr), 1, fp);

        // print section name
        name = SectNames + sectHdr.sh_name;
        if (!strcmp(name, ".dynsym"))
            dynsym_idx = idx;
        if (!strcmp(name, ".rela.plt"))
            rela_idx = idx;
        printf("%u %s\n",  idx, name);
    }

    // find symbol name in .dynsym
    Elf64_Shdr dynsym_sectHdr;
    fseek(fp, elfHdr.e_shoff + dynsym_idx * sizeof(sectHdr), SEEK_SET);
    fread(&dynsym_sectHdr, sizeof(sectHdr), 1, fp);
    Elf64_Sym *symNames;
    symNames = malloc(dynsym_sectHdr.sh_size);
    fseek(fp, dynsym_sectHdr.sh_offset, SEEK_SET);
    fread(symNames, sizeof(Elf64_Sym), dynsym_sectHdr.sh_size / sizeof(Elf64_Sym), fp);

    // find symbol names in .dynstr
    Elf64_Shdr sym_sectHdr;
    fseek(fp, elfHdr.e_shoff + dynsym_sectHdr.sh_link * sizeof(sectHdr), SEEK_SET);
    fread(&sym_sectHdr, sizeof(sym_sectHdr), 1, fp);
    // 指向起始位子
    char *strSymNames;
    strSymNames = malloc(sym_sectHdr.sh_size);
    fseek(fp, sym_sectHdr.sh_offset, SEEK_SET);
    fread(strSymNames, sym_sectHdr.sh_size, 1, fp);


    // find got offset in rela
    fseek(fp, elfHdr.e_shoff + rela_idx * sizeof(sectHdr), SEEK_SET);
    fread(&sectHdr, sizeof(sectHdr), 1, fp);
    Elf64_Rela rela;

    long func_addr;

    for (int idx = 0; idx < (sectHdr.sh_size / sizeof(rela)); idx++)
    {
        const char *name = "";
        //https://docs.oracle.com/cd/E19253-01/819-7050/chapter6-54839/index.html
        fseek(fp, sectHdr.sh_offset + idx * sizeof(rela), SEEK_SET);
        //seek位子 看在第幾格(idx)
        fread(&rela, sizeof(rela), 1, fp);

        name = strSymNames + symNames[ELF64_R_SYM(rela.r_info)].st_name;
        // print symbol name
        if (!strcmp(name, "open"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_open );
        }
        if (!strcmp(name, "read"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_read );
        }
        if (!strcmp(name, "write"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_write );
        }
        if (!strcmp(name, "connect"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_connect );
        }
        if (!strcmp(name, "getaddrinfo"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_getaddrinfo );
        }
        if (!strcmp(name, "system"))
        {
            func_addr = base + rela.r_offset;
            hijack_got( func_addr, fake_system );
        }
    }
    fclose(fp);

} // got_func

void hijack_got( long hijack_addr, void *func_ptr ){
    int  pagesize = sysconf(_SC_PAGE_SIZE); // page size = 4096
    long page_start = hijack_addr/pagesize * pagesize;
    if( mprotect(page_start, pagesize,  PROT_READ | PROT_WRITE ) != -1 )
        memcpy((void*) hijack_addr, &func_ptr, 8);
    else
        printf("hijack error"); 


} // hijack_got

// ###########################hijack got done###################################
int __libc_start_main( int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), 
                        void (*fini) (void), void (*rtld_fini) (void), void (*stack_end) ) {

    // 將要inject的先存起來
    void *handle;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    typedef void (*fnptr_type)(void);
    typedef int (*orig_func_type)(void *, int, char *[], fnptr_type, fnptr_type, fnptr_type, void*);
    orig_func_type orig_func;
    orig_func =  dlsym( handle, "__libc_start_main");
    dlclose(handle);    
    //##################取得base以及執行黨名稱####################
    
    FILE *file;
    ssize_t read;
    char *line = NULL;
    size_t len = 0;  
    file = fopen("/proc/self/maps", "r");
    static long main_min = 0, main_max = 0;
    int line_num = 0;
    char *cmd;
    char *ch;
    while ((read = getline(&line, &len, file) != -1 ) ) {
        if (line_num == 0 )  {
            // 取得 執行程式 的base
            sscanf(line, "%lx-%lx", &main_min, &main_max);
            if ( ( ch = strstr(line, "/") ) != NULL) {
                cmd = malloc(sizeof(ch));
                strcpy(cmd,ch);
                ch = strstr(cmd, "\n");
                *ch = '\0';
            } // if
            // fprintf(stderr,"%s", line);
        } // if
        line_num++;
    } // while
    fclose(file);

    // ###############################got table###################################
    got_func( cmd, main_min );
    // ###########################################################################
    // file = fopen(getenv("SANDBOX_CONFIG"), "r");
    // // 讀取config黨並且記錄blacklist
    // while ((read = getline(&line, &len, file)  ) != -1 ) {
    //     if (strstr(line, "BEGIN") != NULL)  {
    //         if(strstr(line, "open-blacklist") != NULL) {
    //             open_black = readconfig_open( file);
    //         } // if
    //         else if(strstr(line, "connect-blacklist") != NULL) {
    //             connect_black = readconfig( file );
    //         } // if
    //         else if(strstr(line, "getaddrinfo-blacklist") != NULL) {
    //             getaddrinfo_black = readconfig( file );
    //         } // if
    //         else if(strstr(line, "read-blacklist") != NULL) {
    //             // read_black_this = readconfig( file );
    //             read = getline(&read_black, &len, file);
    //             char* ch = NULL;
    //             if( ch = strstr(read_black, "\n") ) {
    //                 *ch = '\0';
    //             } // if
    //             // read_black_len = strlen( read_black );
    //         } // if            

    //     } // if
    // } // while    
    // free(line);
    // fclose(file);

    sscanf(getenv("LOGGER_FD"),"%d",&this_fd);
    // fake_open( "/etc/passwd", 0, 0 );
    //fake_system( "readelf -r /usr/bin/cat | grep open@"  );

    return orig_func( main, argc, ubp_av, init, fini, rtld_fini, stack_end );

} // __libc_start_main()
