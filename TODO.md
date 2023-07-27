# TODO

List of TODO's I still want to get to

1. Unions, ManuallyDrop added for now, but likely need to implement Copy so we don't have to manage
   them manually,
2. Marshalable trait needs to return a generic type
3. Tpm2bSimple should have a trait that returns the slice of the buffer actually used, not the
   whole thing.
4. Proper error handling using a Result type.
5. Implement a macro for marshal/unmarshal of simple TPM2Bs.
6. Implement a macro for marshal/unmarshal of TPMS_ types.
7. Implement a macro for marshal/unmarshal of TPMT_ types.
8. Implement a macro for marshal/unmarshal of TPMA_ types.
9. Implement a macro for marshal/unmarshal of TPML_ types.
10. Implement a macro for marshal/unmarshal of TPMU_ types.