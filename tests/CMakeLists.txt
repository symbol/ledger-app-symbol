cmake_minimum_required(VERSION 3.10)

project(SymbolTests)

add_executable(test_transaction_parser
    test_transaction_parser.c
    ../src/xym/xym_helpers.c        
    ../src/xym/parse/xym_parse.c
    ../src/xym/format/fields.c
    ../src/xym/format/format.c
    ../src/xym/format/printers.c
    ../src/xym/format/readers.c    
    ../src/base32.c
    ../src/buffer.c
)

target_compile_options(test_transaction_parser PRIVATE -Wall -Wextra -pedantic -Werror)
add_compile_definitions(test_transaction_parser PRIVATE FUZZ)
target_include_directories(test_transaction_parser PRIVATE . ../src ../src/xym)
target_link_libraries(test_transaction_parser PRIVATE cmocka)
