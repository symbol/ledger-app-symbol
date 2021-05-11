#include "buffer.h"


bool buffer_can_read(const buffer_t *buffer, size_t n) 
{
    return ( (buffer->size - buffer->offset) >= n ); 
}

bool buffer_seek_set(buffer_t *buffer, size_t offset) 
{
    if (offset > buffer->size) 
    {
        return false;
    }

    buffer->offset = offset;

    return true;
}

bool buffer_seek(buffer_t *buffer, size_t offset) 
{
    if( buffer->offset + offset < buffer->offset ||   // overflow
        buffer->offset + offset > buffer->size      ) // exceed buffer size
    {
        return false;
    }

    buffer->offset += offset;

    return true;
}


uint8_t* buffer_offset_ptr( buffer_t* buffer )
{
    return (buffer->ptr + buffer->offset);
}

uint8_t* buffer_offset_ptr_and_seek( buffer_t* buffer, size_t n)
{
    uint8_t*   out  = buffer_offset_ptr( buffer );
    const bool succ = buffer_seek( buffer, n );
    
    if( !succ ) { out = NULL; }

    return out;
}