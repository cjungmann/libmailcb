// -*- compile-command: "gcc -Wall -Werror -DBUFFREAD_MAIN -ggdb -U NDEBUG -o buffread buffread.c " -*-

#include <stdio.h>     // for fprintf()
#include <stdlib.h>    // for exit()
#include <errno.h>     // to use errno global variable
#include <string.h>    // for memmove(), strerror()
#include <assert.h>

#include "buffread.h"

// Private, internal functions
const char *find_bc_end_of_line(const char *cur_line, const char *limit);
const char *find_bc_start_of_next_line(const char *line_ending_char, const char *limit);
void read_into_bc_buffer(BuffControl *bc);

/**
 * @brief Simple implementation of BReader function pointer using a FILE*
 */
size_t bc_file_reader(void *filestream, char *buffer, int buffer_len)
{
   FILE *f = (FILE*)filestream;
   return fread(buffer, 1, buffer_len, f);
}

/**
 * @brief Returns a pointer just past the last character of the line.
 *
 * The function considers character up to, but not including limit.
 */
const char *find_bc_end_of_line(const char *cur_line, const char *limit)
{
   const char *ptr = cur_line;
   while (ptr < limit)
   {
      if (*ptr == '\n' || *ptr == '\r')
         return ptr;
      else
         ++ptr;
   }

   return NULL;
}

const char *find_bc_start_of_next_line(const char *line_ending_char, const char *limit)
{
   // If there is a character beyond newline, that's
   if (*line_ending_char == '\n' && line_ending_char+1 < limit)
      return line_ending_char + 1;
   else if (++line_ending_char < limit && *line_ending_char == '\n')
   {
      assert(*(line_ending_char-1) == '\r');
      return line_ending_char + 1;
   }
   else
      return NULL;
}

/**
 * @brief Read more data to fill buffer.
 *
 * These are the assumptions about the current data of the buff control:
 * - bc->cur_line is NULL or points to the beginning of a line
 * - This function is only called when there is no line or an incomplete line
 *
 */
void read_into_bc_buffer(BuffControl *bc)
{
   assert(!bc->reached_EOF);

   char *read_target = bc->buffer;
   int bytes_to_read = bc->buff_len;
   char last_char_of_buffer = '\0';

   if (bc->end_of_data)
      last_char_of_buffer = *(bc->end_of_data - 1);

   // For incomplete line, shift the memory and calculate how
   // much room remains in the buffer for additional data
   if (bc->cur_line)
   {
      int offset = bc->end_of_data - bc->cur_line;
      memmove(bc->buffer, bc->cur_line, offset);
      bytes_to_read -= offset;

      read_target = &bc->buffer[offset];
   }

   // Get the data
   int bytes_read = (*bc->breader)(bc->data_source, read_target, bytes_to_read);

   if (bytes_read == 0)
      bc->reached_EOF = 1;

   if (bc->log_reads)
      fprintf(stderr, "[34;1mread %4d characters into the buffer.[m\n", bytes_read);

   // Set BuffControl to new situation:
   bc->end_of_data = &read_target[bytes_read];
   bc->cur_line = bc->buffer;

   if (last_char_of_buffer == '\r' && *bc->cur_line == '\n')
      ++bc->cur_line;
}

/**
 * @brief Prepares a BuffControl structure for use and executes the initial read
 *
 * @param bc          Pointer to a BuffControl variable.  Function clears before setting members
 * @param buffer      Pointer to a block of memory into which the source contents will be written
 * @param buff_len    Length, in bytes, of the buffer
 * @param breader     Pointer to function that fills the buffer
 * @param data_source Generic data pointer to context used by breader parameter
 *
 * This function prepares the BuffControl structure and 
 */
void init_buff_control(BuffControl *bc,
                       char *buffer,
                       int buff_len,
                       BReader breader,
                       void *data_source)
{
   memset(bc, 0, sizeof(BuffControl));

   bc->buffer      = buffer;
   bc->buff_len    = buff_len;
   bc->data_source = data_source;
   bc->breader     = breader;

   read_into_bc_buffer(bc);
}

/**
 * @brief Through pointer parameters, this function returns the current line to the calling function.
 *
 * @param bc       Initialized and valid BuffControl object
 * @param line     Pointer-to-pointer to an unterminated char string.  This is
 *                 where the function returns the line.
 * @param line_len The function returns the line length in this parameter.  Use this
 *                 value to know where the line ends (there will likely be no \0
 *                 terminator.
 *
 * @return 0 for no line, 1 for valid line.
 *
 * This function returns the current line.  After retrieving the line, the
 * BuffControl object will be updated to point to the next line.
 *
 * Important note: All lines are counted through the new line character(s), with
 *                 the possible exception of the last line, which can also be
 *                 terminated by an EOF.  That means that an empty final line
 *                 will be ignored.
 */
int get_bc_line(BuffControl *bc, const char **line, int *line_len)
{
   const char *end_of_line, *start_of_next_line;

   // Check for signal that no more lines are available
   if (bc->cur_line == NULL)
   {
      *line = NULL;
      *line_len = 0;
      return 0;
   }

   // See if the end of line is available
   end_of_line = find_bc_end_of_line(bc->cur_line, bc->end_of_data);
   if (!end_of_line && bc->reached_EOF)
      end_of_line = bc->end_of_data;

   if (end_of_line)
   {
      // Before setting the 'return' parameters, make
      // sure that the start of the next line is in the
      // current buffer contents:
      start_of_next_line = find_bc_start_of_next_line(end_of_line, bc->end_of_data);
      if (start_of_next_line || bc->reached_EOF)
      {
         *line = bc->cur_line;
         *line_len = end_of_line - bc->cur_line;

         // If reached the end of the message:
         if (*line_len==1 && **line=='.')
            bc->reached_EOF = 1;

         if (bc->reached_EOF)
            bc->cur_line = NULL;
         else
            bc->cur_line = start_of_next_line;

         return 1;
      }
   }
      
   // If we've fallen through the preceding conditions,
   // we need to get more data before we can return anything.
   read_into_bc_buffer(bc);
   return get_bc_line(bc, line, line_len);
}

#ifdef BUFFREAD_MAIN

#include <stdlib.h>

void read_the_file(BuffControl *bc)
{
   const char *line;
   int line_len;
   int counter = 0;
      
   while(get_bc_line(bc, &line, &line_len))
      printf("line [43;1m%3d[m with %2d characters:  %.*s\n", ++counter, line_len, line_len, line);
}

int main(int argc, const char **argv)
{
   char buffer[1024];
   BuffControl bc;

   if (argc<2)
   {
      printf("Must name a file from which to read.\n");
   }
   else
   {
      FILE *fstream = fopen(argv[1], "r");
      if (fstream)
      {
         init_buff_control(&bc, buffer, sizeof(buffer), bc_file_reader, (void*)fstream);

         // Set for debugging, show timing and size of reads to stderr:
         /* bc.log_reads = 1; */

         read_the_file(&bc);

         fclose(fstream);

         return 0;
      }
      else
         printf("Failed to open \"%s\" (%s).\n", argv[1], strerror(errno)); 
   }

   return 1;
}


#endif // INCLUDE_MAIN
