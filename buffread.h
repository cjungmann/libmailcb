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

   // Debugging flag
   int log_reads;

} BuffControl;

int get_bc_line(BuffControl *bc, const char **line, int *line_len);

void init_buff_control(BuffControl *bc,
                       char *buffer,
                       int buff_len,
                       BReader breader,
                       void *data_source);


#endif
