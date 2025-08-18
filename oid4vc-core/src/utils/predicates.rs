/// Generic predicate function that validates that a vector is not empty. For use in our nutype structs.
pub fn not_empty<T>(vec: &[T]) -> bool {
    !vec.is_empty()
}
