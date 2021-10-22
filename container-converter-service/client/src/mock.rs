use crate::operations::{Operation, TupleRef, UrlEncode};
use mockito::Matcher;
use serde::Serialize;
use std::collections::HashMap;
use std::marker::PhantomData;

pub struct MockBuilder<O: Operation> {
    body_matcher: mockito::Matcher,
    path: O::PathParams,
    query: Option<O::QueryParams>,
    status: Option<hyper::status::StatusCode>,
    output: O::Output,
    phantom: PhantomData<O>,
}

pub type Mock = mockito::Mock;

impl<O> MockBuilder<O>
    where O: Operation,
          O::Output: Serialize,
{
    pub(crate) fn new(path: O::PathParams, output: O::Output) -> Self {
        Self {
            body_matcher: Matcher::Any,
            path,
            query: None,
            status: None,
            output,
            phantom: PhantomData
        }
    }

    pub fn with_status(mut self, status: hyper::status::StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    pub fn match_query(mut self, query: O::QueryParams) -> Self {
        self.query = Some(query);
        self
    }

    pub fn match_body_exact(mut self, body: O::Body) -> Self {
        self.body_matcher = Matcher::Json(serde_json::to_value(&body).unwrap());
        self
    }

    pub fn match_body<M: Into<Matcher>>(mut self, body: M) -> Self {
        self.body_matcher = body.into();
        self
    }

    pub fn create(self) -> Mock {
        let path = {
            let mut path = O::path(self.path.as_ref(), None);
            if path.ends_with("?") {
                path.truncate(path.len() - 1)
            }
            path
        };
        let query_matcher = self.query.map_or(Matcher::Any, |query| {
            let mut params = HashMap::new();
            query.url_encode(&mut params);
            Matcher::AllOf(params.into_iter().map(|(param, value)| Matcher::UrlEncoded(param.to_owned(), value)).collect())
        });
        mockito::mock(O::method().as_ref(), path.as_str())
            .with_status(self.status.map_or(200, |s| s.to_u16().into()))
            .with_body(serde_json::to_string(&self.output).unwrap())
            .expect_at_least(1)
            .match_query(query_matcher)
            .match_body(self.body_matcher)
            .create()
    }
}

pub struct NitroEnclavesConverterApiMock;

impl NitroEnclavesConverterApiMock {
    pub fn mock<O>(&self, path: O::PathParams, output: O::Output) -> MockBuilder<O>
        where O: Operation,
              O::Output: Serialize
    {
        MockBuilder::new(path, output)
    }

    pub fn server_url() -> String {
        mockito::server_url()
    }
}
