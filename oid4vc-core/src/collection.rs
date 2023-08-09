use crate::SubjectSyntaxType;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct Collection<T: ?Sized>(pub HashMap<SubjectSyntaxType, Arc<T>>);

impl<T: ?Sized> Collection<T> {
    pub fn get(&self, subject_syntax_type: &SubjectSyntaxType) -> Option<&Arc<T>> {
        self.0.get(subject_syntax_type)
    }

    pub fn add(&mut self, subject_syntax_type: SubjectSyntaxType, subject: Arc<T>) {
        self.0.insert(subject_syntax_type, subject);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SubjectSyntaxType, &Arc<T>)> {
        self.0.iter()
    }
}

impl<T: ?Sized> Default for Collection<T> {
    fn default() -> Self {
        Collection(HashMap::new())
    }
}

impl<T: ?Sized, const N: usize> From<[(SubjectSyntaxType, Arc<T>); N]> for Collection<T> {
    fn from(items: [(SubjectSyntaxType, Arc<T>); N]) -> Self {
        Collection(items.iter().cloned().collect())
    }
}

impl<T: ?Sized> From<Vec<(SubjectSyntaxType, Arc<T>)>> for Collection<T> {
    fn from(items: Vec<(SubjectSyntaxType, Arc<T>)>) -> Self {
        Collection(items.iter().cloned().collect())
    }
}
