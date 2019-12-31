#ifndef BUFFREAD_C
#define BUFFREAD_C

typedef size_t (*BReader)(void *source, char *buffer, int chars_to_read);

typedef struct _buff_control
{
   char *buffer;
   int buff_len;
   void *data_source;    // generic pointer to readable source
   BReader breader;      // function pointer to use readable source

   // Range-confirmation pointer to end of data:
   const char *end_of_data;

   // Always pointing to a line
   const char *cur_line;

   // flag to indicate EOF reached
   int reached_EOF;

} BuffControl;

const char *find_bc_end_of_line(const char *cur_line, const char *limit);
const char *find_bc_start_of_next_line(const char *line_ending_char, const char *limit);


void read_into_bc_buffer(BuffControl *bc);

int get_bc_line(BuffControl *bc, const char **line, int *line_len);

void init_buff_control(BuffControl *bc,
                       char *buffer,
                       int buff_len,
                       void *data_source,
                       BReader breader);


#endif
