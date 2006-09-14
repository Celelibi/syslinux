/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2006 H. Peter Anvin - All Rights Reserved
 *
 *   Permission is hereby granted, free of charge, to any person
 *   obtaining a copy of this software and associated documentation
 *   files (the "Software"), to deal in the Software without
 *   restriction, including without limitation the rights to use,
 *   copy, modify, merge, publish, distribute, sublicense, and/or
 *   sell copies of the Software, and to permit persons to whom
 *   the Software is furnished to do so, subject to the following
 *   conditions:
 *
 *   The above copyright notice and this permission notice shall
 *   be included in all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *   OTHER DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <png.h>
#include <tinyjpeg.h>
#include <com32.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <minmax.h>
#include "vesa.h"
#include "video.h"
#include "fmtpixel.h"

static size_t filesize(FILE *fp)
{
  struct stat st;
  if (fstat(fileno(fp), &st))
    return 0;
  else
    return st.st_size;
}

/*** FIX: This really should be alpha-blended with color index 0 */

/* For best performance, "start" should be a multiple of 4, to assure
   aligned dwords. */
static void draw_background_line(int line, int start, int npixels)
{
  uint8_t line_buf[VIDEO_X_SIZE*4], *lbp;
  uint32_t *bgptr = &__vesacon_background[line][start];
  unsigned int bytes_per_pixel = __vesacon_bytes_per_pixel;
  enum vesa_pixel_format pixel_format = __vesacon_pixel_format;
  uint8_t *fbptr = (uint8_t *)__vesa_info.mi.lfb_ptr +
    (line*VIDEO_X_SIZE+start)*bytes_per_pixel;

  lbp = line_buf;
  while (npixels--)
    lbp = format_pixel(lbp, *bgptr++, pixel_format);
    
  memcpy(fbptr, line_buf, lbp-line_buf);
}

/* This draws the border, then redraws the text area */
static void draw_background(void)
{
  int i;
  const int bottom_border = VIDEO_BORDER +
    (TEXT_PIXEL_ROWS % __vesacon_font_height);
  const int right_border = VIDEO_BORDER + (TEXT_PIXEL_COLS % FONT_WIDTH);
  
  for (i = 0; i < VIDEO_BORDER; i++)
    draw_background_line(i, 0, VIDEO_X_SIZE);
  
  for (i = VIDEO_BORDER; i < VIDEO_Y_SIZE-bottom_border; i++) {
    draw_background_line(i, 0, VIDEO_BORDER);
    draw_background_line(i, VIDEO_X_SIZE-right_border, right_border);
  }

  for (i = VIDEO_Y_SIZE-bottom_border; i < VIDEO_Y_SIZE; i++)
    draw_background_line(i, 0, VIDEO_X_SIZE);

  __vesacon_redraw_text();
}

static int read_png_file(FILE *fp)
{
  png_structp png_ptr = NULL;
  png_infop info_ptr = NULL;
  png_infop end_ptr = NULL;
#if 0
  png_color_16p image_background;
  static const png_color_16 my_background = {0,0,0,0,0};
#endif
  png_bytep row_pointers[VIDEO_Y_SIZE];
  int passes;
  int i;
  int rv = -1;

  png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
				   NULL, NULL, NULL);

  info_ptr = png_create_info_struct(png_ptr);
  end_ptr = png_create_info_struct(png_ptr);

  if (!png_ptr || !info_ptr || !end_ptr ||
      setjmp(png_jmpbuf(png_ptr)))
    goto err;

  png_init_io(png_ptr, fp);
  png_set_sig_bytes(png_ptr, 8);

  png_set_user_limits(png_ptr, VIDEO_X_SIZE, VIDEO_Y_SIZE);

  png_read_info(png_ptr, info_ptr);

  /* Set the appropriate set of transformations.  We need to end up
     with 32-bit BGRA format, no more, no less. */

  switch (info_ptr->color_type) {
  case PNG_COLOR_TYPE_GRAY_ALPHA:
    png_set_gray_to_rgb(png_ptr);
    /* fall through */

  case PNG_COLOR_TYPE_RGB_ALPHA:
    break;

  case PNG_COLOR_TYPE_GRAY:
    png_set_gray_to_rgb(png_ptr);
    /* fall through */

  case PNG_COLOR_TYPE_RGB:
    if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS))
      png_set_tRNS_to_alpha(png_ptr);
    else
      png_set_add_alpha(png_ptr, ~0, PNG_FILLER_AFTER);
    break;

  case PNG_COLOR_TYPE_PALETTE:
    png_set_palette_to_rgb(png_ptr);
    break;

  default:
    /* Huh? */
    break;
  }

  png_set_bgr(png_ptr);

  if (info_ptr->bit_depth == 16)
    png_set_strip_16(png_ptr);
  else if (info_ptr->bit_depth < 8)
    png_set_packing(png_ptr);

#if 0
  if (png_get_bKGD(png_ptr, info_ptr, &image_background))
    png_set_background(png_ptr, image_background,
		       PNG_BACKGROUND_GAMMA_FILE, 1, 1.0);
  else
    png_set_background(png_ptr, &my_background,
		       PNG_BACKGROUND_GAMMA_SCREEN, 0, 1.0);
#endif

  /* Whew!  Now we should get the stuff we want... */
  for (i = 0; i < (int)info_ptr->height; i++)
    row_pointers[i] = (void *)__vesacon_background[i];

  passes = png_set_interlace_handling(png_ptr);

  for (i = 0; i < passes; i++)
    png_read_rows(png_ptr, row_pointers, NULL, info_ptr->height);

  rv = 0;

 err:
  if (png_ptr)
    png_destroy_read_struct(&png_ptr, (png_infopp)NULL, (png_infopp)NULL);
  return rv;
}

static int jpeg_sig_cmp(uint8_t *bytes, int len)
{
  (void)len;
  return (bytes[0] == 0xff && bytes[1] == 0xd8) ? 0 : -1;
}

static int read_jpeg_file(FILE *fp, uint8_t *header, int len)
{
  struct jdec_private *jdec = NULL;
  unsigned char *jpeg_file = NULL;
  size_t length_of_file = filesize(fp);
  unsigned int width, height;
  int rv = -1;
  unsigned char *components[1];
  unsigned int bytes_per_row[1];

  jpeg_file = malloc(length_of_file);
  if (!jpeg_file)
    goto err;

  memcpy(jpeg_file, header, len);
  if (fread(jpeg_file+len, 1, length_of_file-len, fp) != length_of_file-len)
    goto err;

  jdec = tinyjpeg_init();
  if (!jdec)
    goto err;

  if (tinyjpeg_parse_header(jdec, jpeg_file, length_of_file) < 0)
    goto err;

  tinyjpeg_get_size(jdec, &width, &height);
  if (width > VIDEO_X_SIZE || height > VIDEO_Y_SIZE)
    goto err;

  components[0] = (void *)&__vesacon_background[0];
  tinyjpeg_set_components(jdec, components, 1);
  bytes_per_row[0] = VIDEO_X_SIZE << 2;
  tinyjpeg_set_bytes_per_row(jdec, bytes_per_row, 1);

  tinyjpeg_decode(jdec, TINYJPEG_FMT_BGRA32);

  rv = 0;

 err:
  /* Don't use tinyjpeg_free() here, since we didn't allow tinyjpeg
     to allocate the frame buffer */
  if (jdec)
    free(jdec);

  if (jpeg_file)
    free(jpeg_file);

  return rv;
}

int vesacon_load_background(const char *filename)
{
  FILE *fp;
  uint8_t header[8];
  int rv = 1;

  if (!filename) {
    draw_background();
    return 0;
  }

  fp = fopen(filename, "r");

  if (!fp)
    goto err;

  if (fread(header, 1, 8, fp) != 8)
    goto err;

  if (!png_sig_cmp(header, 0, 8)) {
    rv = read_png_file(fp);
  } else if (!jpeg_sig_cmp(header, 8)) {
    rv = read_jpeg_file(fp, header, 8);
  }

  /* This actually displays the stuff */
  draw_background();

 err:
  if (fp)
    fclose(fp);

  return rv;
}

int __vesacon_init_background(void)
{
  /* The BSS clearing has already cleared __vesacon_background */

  /* The VESA BIOS has already cleared the screen */
  return 0;
}
