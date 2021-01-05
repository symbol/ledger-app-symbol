#include <malloc.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>

#include "cmocka.h"

#include "parse/xym_parse.h"
#include "format/format.h"
#include "apdu/global.h"  // FIXME: transaction_context_t should be defined elsewhere

transaction_context_t transactionContext;

typedef struct {
    const char *field_name;
    const char *field_value;
} result_entry_t;

static uint8_t *load_transaction_data(const char *filename, size_t *size) {
    uint8_t *data;

    FILE *f = fopen(filename, "rb");
    assert_non_null(f);

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    data = malloc(filesize);
    assert_non_null(data);
    assert_int_equal(fread(data, 1, filesize, f), filesize);
    *size = filesize;
    fclose(f);
    return data;
}

static void check_transaction_results(const char *filename, int num_fields, const result_entry_t *expected) {
    parse_context_t context = {0};
    char field_name[MAX_FIELDNAME_LEN];
    char field_value[MAX_FIELD_LEN];

    size_t tx_length;
    uint8_t * const tx_data = load_transaction_data(filename, &tx_length);
    assert_non_null(tx_data);

    context.data = tx_data;
    context.length = tx_length;

    assert_int_equal(parse_txn_context(&context), 0);
    assert_int_equal(context.result.numFields, num_fields);

    for (int i = 0; i < context.result.numFields; i++) {
        const field_t *field = &context.result.fields[i];
        resolve_fieldname(field, field_name);
        format_field(field, field_value);
        assert_string_equal(expected[i].field_name, field_name);
        assert_string_equal(expected[i].field_value, field_value);
    }
    free(tx_data);
    return;
}

static void test_parse_transfer_transaction(void **state) {
    (void) state;

    const result_entry_t expected[6] = {
        {"Transaction Type", "Transfer"},
        {"Recipient", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Amount", "45 XYM"},
        {"Message Type", "Plain text"},
        {"Message", "This is a test message"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/transfer_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_transfer_transaction_not_xym(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Transfer"},
        {"Recipient", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Mosaics", "Found 1"},
        {"Unknown Mosaic", "Divisibility and levy cannot be shown"},
        {"Amount", "45000000 micro 0x5E62990DCAC5B21A"},
        {"Message Type", "Plain text"},
        {"Message", "This is a test message"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/transfer_transaction_not_xym.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_create_mosaic(void **state) {
    (void) state;

    const result_entry_t expected[14] = {
        {"Transaction Type", "Aggregate Complete"},
        {"Agg. Tx Hash", "E5F37FE3F83F4F0A2F21E7CF25F75CF29A20D7929CBEB7EB552EDA846969281F"},
        {"Inner TX Type", "Mosaic definition"},
        {"Mosaic ID", "532CB823113F2471"},
        {"Divisibility", "0"},
        {"Duration", "0d 0h 5m"},
        {"Transferable", "Yes"},
        {"Supply Mutable", "Yes"},
        {"Restrictable", "Yes"},
        {"Inner TX Type", "Mosaic Supply Change"},
        {"Mosaic ID", "532CB823113F2471"},
        {"Change Direction", "Increase"},
        {"Change Amount", "1000000"},
        {"Fee", "2 XYM"},
    };

    check_transaction_results("../testcases/create_mosaic.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_create_namespace(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Namespace Registration"},
        {"Namespace Type", "Root namespace"},
        {"Name", "foo576sgnlxdnfbdx"},
        {"Duration", "60d 0h 0m"},
        {"Fee", "2 XYM"},
    };

    check_transaction_results("../testcases/create_namespace.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_create_sub_namespace(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Namespace Registration"},
        {"Namespace Type", "Sub namespace"},
        {"Name", "foo576sgnlxdnfbdx"},
        {"Parent ID", "000000000002A300"},
        {"Fee", "2 XYM"},
    };

    check_transaction_results("../testcases/create_sub_namespace.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_supply_change_mosaic(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Mosaic Supply Change"},
        {"Mosaic ID", "7CDF3B117A3C40CC"},
        {"Change Direction", "Increase"},
        {"Change Amount", "1000000"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/supply_change_mosaic.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_link_namespace_to_mosaic(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Mosaic Alias"},
        {"Alias Type", "Unlink address"},
        {"Namespace ID", "82A9D1AC587EC054"},
        {"Mosaic ID", "7CDF3B117A3C40CC"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/link_namespace_to_mosaic.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_link_namespace_to_address(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Address Alias"},
        {"Alias Type", "Link address"},
        {"Namespace ID", "82A9D1AC587EC054"},
        {"Address", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/link_namespace_to_address.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_account_address_restriction(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Account Address Restriction"},
        {"Addition Count", "1 address(es)"},
        {"Address", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Deletion Count", "Not change"},
        {"Restriction Flag", "Block"},
        {"Restriction Flag", "Imcoming"},
        {"Restriction Flag", "Address"},
        {"Fee", "0.16 XYM"}
    };

    check_transaction_results("../testcases/account_address_restriction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_account_mosaic_restriction(void **state) {
    (void) state;

    const result_entry_t expected[7] = {
        {"Transaction Type", "Account Mosaic Restriction"},
        {"Addition Count", "1 mosaic(s)"},
        {"Mosaic ID", "5BA212858B2B48BC"},
        {"Deletion Count", "Not change"},
        {"Restriction Flag", "Block"},
        {"Restriction Flag", "Mosaic"},
        {"Fee", "0.144 XYM"}
    };

    check_transaction_results("../testcases/account_mosaic_restriction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_account_operation_restriction(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Account Operation Restriction"},
        {"Addition Count", "1 operation(s)"},
        {"Operation Type", "Account Key Link"},
        {"Deletion Count", "Not change"},
        {"Restriction Flag", "Block"},
        {"Restriction Flag", "Outgoing"},
        {"Restriction Flag", "Transaction Type"},
        {"Fee", "0.138 XYM"}
    };

    check_transaction_results("../testcases/account_operation_restriction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_account_multisig(void **state) {
    (void) state;

    const result_entry_t expected[10] = {
        {"Transaction Type", "Aggregate Bonded"},
        {"Agg. Tx Hash", "043D6F6E851CAE4ED2B975AEEF61DFDF00B85BBB2503AC23DD7586E3C0B07956"},
        {"Inner TX Type", "Multisig Account Modification"},
        {"Address Add Num", "2"},
        {"Address", "TALSLGUUF5VOB2RSWAPDNBUHIBKTNZQREXWPOAI"},
        {"Address", "TBFXGDVDW4TMYEVJ7L3YWTJXGVH7Q4RNXOKQCNY"},
        {"Address Del Num", "0"},
        {"Min Approval", "Add 1 address(es)"},
        {"Min Removal", "Add 1 address(es)"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/account_multisig.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_hash_lock_account_multisig(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Funds Lock"},
        {"Lock Quantity", "10 XYM"},
        {"Duration", "0d 4h 0m"},
        {"Tx Hash", "2B51EBCBC3E40EFE8AF68A0408F5A72474B1327A64E3E3B47D9B139230C7833B"},
        {"Fee", "2 XYM"}
    };

    check_transaction_results("../testcases/hash_lock_account_multisig.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_multisig_transfer_transaction(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Aggregate Bonded"},
        {"Agg. Tx Hash", "4941C270B56778E01629FC82EDDC622668F076CE1583AFCCA3F6DE7FE03615BB"},
        {"Inner TX Type", "Transfer"},
        {"Recipient", "TBKQPST7HUOJA2PBNYNA7TT4LLKGA5BB5UY6M4Y"},
        {"Amount", "10 XYM"},
        {"Message Type", "Plain text"},
        {"Message", "Test message"},
        {"Fee", "0.03024 XYM"},
    };

    check_transaction_results("../testcases/multisig_transfer_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_multisig_create_mosaic(void **state) {
    (void) state;

    const result_entry_t expected[14] = {
        {"Transaction Type", "Aggregate Bonded"},
        {"Agg. Tx Hash", "705B456E99A2FA7DA3D4F02ABB1993774426B8095705C2116E6FB59E95A2587D"},
        {"Inner TX Type", "Mosaic definition"},
        {"Mosaic ID", "78CA2F4797C65A64"},
        {"Divisibility", "0"},
        {"Duration", "Unlimited"},
        {"Transferable", "Yes"},
        {"Supply Mutable", "Yes"},
        {"Restrictable", "No"},
        {"Inner TX Type", "Mosaic Supply Change"},
        {"Mosaic ID", "78CA2F4797C65A64"},
        {"Change Direction", "Increase"},
        {"Change Amount", "500000000"},
        {"Fee", "0.033696 XYM"},
    };

    check_transaction_results("../testcases/multisig_create_mosaic.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_multisig_create_namespace(void **state) {
    (void) state;

    const result_entry_t expected[7] = {
        {"Transaction Type", "Aggregate Bonded"},
        {"Agg. Tx Hash", "B96E1C08F8434BFDC4D1F292EB3F911B1A3C5B3EE102887A8ACDD75A79A4BB62"},
        {"Inner TX Type", "Namespace Registration"},
        {"Namespace Type", "Root namespace"},
        {"Name", "multisig"},
        {"Duration", "60d 0h 0m"},
        {"Fee", "0.026784 XYM"}
    };

    check_transaction_results("../testcases/multisig_create_namespace.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_hash_lock_multisig_create_namespace(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Funds Lock"},
        {"Lock Quantity", "10 XYM"},
        {"Duration", "0d 8h 20m"},
        {"Tx Hash", "E019A4A92002505B8B5029AE556958ADCDFBEDAC26C2F79DE1668C5BC588EDF7"},
        {"Fee", "0.019872 XYM"},
    };

    check_transaction_results("../testcases/hash_lock_multisig_create_namespace.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_multisig_create_sub_namespace(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Namespace Registration"},
        {"Namespace Type", "Sub namespace"},
        {"Name", "sub_namespace_multisig"},
        {"Parent ID", "D64FAC0976CC0914"},
        {"Fee", "0.018144 XYM"}
    };

    check_transaction_results("../testcases/multisig_create_sub_namespace.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_cosignature_transaction(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Aggregate Bonded"},
        {"Agg. Tx Hash", "0EFE6E4A881D312984767CABBE53DAC00419E179932A5C784B51132FBE5F7C88"},
        {"Detail TX Type", "Transfer"},
        {"Recipient", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Amount", "10 XYM"},
        {"Message Type", "Plain text"},
        {"Message", "SDV"},
        {"Fee", "0.48 XYM"}
    };

    check_transaction_results("../testcases/cosignature_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_account_metadata_transaction(void **state) {
    (void) state;

    const result_entry_t expected[8] = {
        {"Transaction Type", "Aggregate Complete"},
        {"Agg. Tx Hash", "5F221AD2C6D297E683692CE332B24157057E6FB43A832F18C13495EC49544E08"},
        {"Inner TX Type", "Account Metadata"},
        {"Target Address", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Metadata Key", "AB8385A30DFCEA7A"},
        {"Value", "this is the value field of account metadata"},
        {"Value Size Delta", "Increase 43 byte(s)"},
        {"Fee", "0.296 XYM"}
    };

    check_transaction_results("../testcases/account_metadata_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_mosaic_metadata_transaction(void **state) {
    (void) state;

    const result_entry_t expected[9] = {
        {"Transaction Type", "Aggregate Complete"},
        {"Agg. Tx Hash", "FD62E4D107693B6B0A7D862F2BBE49695565764AE41AE0D0344C47AE82DCB00C"},
        {"Inner TX Type", "Mosaic Metadata"},
        {"Target Address", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Mosaic ID", "6E32F5200421C596"},
        {"Metadata Key", "D00C0B75EFB5FA9F"},
        {"Value", "This is the mosaic metadata value field"},
        {"Value Size Delta", "Increase 39 byte(s)"},
        {"Fee", "0.304 XYM"}
    };

    check_transaction_results("../testcases/mosaic_metadata_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_namespace_metadata_transaction(void **state) {
    (void) state;

    const result_entry_t expected[9] = {
        {"Transaction Type", "Aggregate Complete"},
        {"Agg. Tx Hash", "668FE1351AC31C35536EE3A368F2C2310DD3D7E67A8345050548AE8B6596015D"},
        {"Inner TX Type", "Namespace Metadata"},
        {"Target Address", "TDZKL2HAMOWRVEEF55NVCZ7C6GSWIXCI7IWAESI"},
        {"Namespace ID", "8547528FC63C2AD6"},
        {"Metadata Key", "9E828FFAA77C9D6D"},
        {"Value", "Namespace metadata value field"},
        {"Value Size Delta", "Increase 30 byte(s)"},
        {"Fee", "0.296 XYM"}
    };

    check_transaction_results("../testcases/namespace_metadata_transaction.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_delegated_harvesting(void **state) {
    (void) state;

    const result_entry_t expected[12] = {
        {"Transaction Type", "Aggregate Complete"},
        {"Agg. Tx Hash", "0C8666CEF61F61B78515149A1414455C77A0CCD7C9AD5F39DFE46761AB6556DF"},
        {"Inner TX Type", "Account Key Link"},
        {"Action", "Link"},
        {"Linked Acct. PbK", "00278C080D6B149902E1576723DA6362065D3A134BEE6383827353540492B911"},
        {"Inner TX Type", "Vrf Key Link"},
        {"Action", "Link"},
        {"Linked Vrf PbK", "C1A71431325873D83894977C68C783A4EED7A3391EAFD704BF8500361EC321DB"},
        {"Inner TX Type", "Node Key Link"},
        {"Action", "Link"},
        {"Linked Node PbK", "81890592F960AAEBDA7612C8917FA9C267A845D78D74D4B3651AF093E6775001"},
        {"Fee", "0.0432 XYM"}
    };

    check_transaction_results("../testcases/delegated_harvesting.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

static void test_parse_persistent_harvesting_delegation_transfer(void **state) {
    (void) state;

    const result_entry_t expected[5] = {
        {"Transaction Type", "Transfer"},
        {"Recipient", "TBR6AUIUNBRSXJ34RSCZOJTK4GQNVDEUEDCPMIY"},
        {"Message Type", "Persistent harvesting delegation"},
        {"Harvesting Message", "FE2A8061577301E28AEC26D42EFCE832BE498BB8CFCC7687BC5BC6B22A82F4BA415A7DF13E1DEA994EAD70125CA250DD6CD8AEA8BAE26AD9A8FC9CB45A996E59BD8894E3D618043887E2383A6BB161A18AB58F406D7DFF384CBD6A669FD152E5AD84B372425212CAAECCB712674AA6C737894BB14FADFE93A3E3AF73A34187D49740891C"},
        {"Fee", "0.292 XYM"}
    };

    check_transaction_results("../testcases/persistent_harvesting_delegation_transfer.raw", sizeof(expected) / sizeof(expected[0]), expected);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_transfer_transaction),
        cmocka_unit_test(test_parse_transfer_transaction_not_xym),
        cmocka_unit_test(test_parse_create_mosaic),
        cmocka_unit_test(test_parse_create_namespace),
        cmocka_unit_test(test_parse_create_sub_namespace),
        cmocka_unit_test(test_parse_supply_change_mosaic),
        cmocka_unit_test(test_parse_link_namespace_to_mosaic),
        cmocka_unit_test(test_parse_link_namespace_to_address),
        cmocka_unit_test(test_parse_account_address_restriction),
        cmocka_unit_test(test_parse_account_mosaic_restriction),
        cmocka_unit_test(test_parse_account_operation_restriction),
        cmocka_unit_test(test_parse_account_multisig),
        cmocka_unit_test(test_parse_hash_lock_account_multisig),
        cmocka_unit_test(test_parse_multisig_transfer_transaction),
        cmocka_unit_test(test_parse_multisig_create_mosaic),
        cmocka_unit_test(test_parse_multisig_create_namespace),
        cmocka_unit_test(test_parse_hash_lock_multisig_create_namespace),
        cmocka_unit_test(test_parse_multisig_create_sub_namespace),
        cmocka_unit_test(test_parse_cosignature_transaction),
        cmocka_unit_test(test_parse_account_metadata_transaction),
        cmocka_unit_test(test_parse_mosaic_metadata_transaction),
        cmocka_unit_test(test_parse_namespace_metadata_transaction),
        cmocka_unit_test(test_parse_delegated_harvesting),
        cmocka_unit_test(test_parse_persistent_harvesting_delegation_transfer)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
