use hyper::method::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write;
use uuid::Uuid;

pub trait Operation {
    type PathParams: for<'a> TupleRef<'a>;
    type QueryParams: UrlEncode;
    type Body: Serialize;
    type Output: for<'de> Deserialize<'de>;

    fn method() -> Method;
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String;

    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        Some(serde_json::to_value(body).expect("serialize to value"))
    }
}

pub trait UrlEncode {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>);

    fn encode(&self) -> String {
        let mut m = HashMap::new();
        self.url_encode(&mut m);
        let mut output = String::with_capacity(64);
        for (i, (k, v)) in m.into_iter().enumerate() {
            if i > 0 {
                output.push('&');
            }
            write!(&mut output, "{}={}", k, v).unwrap(); // FIXME: formurlencode
        }
        output
    }
}

impl UrlEncode for () {
    fn url_encode(&self, _m: &mut HashMap<&'static str, String>) {}
}

impl<T: UrlEncode> UrlEncode for Option<T> {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>) {
        if let Some(val) = self {
            val.url_encode(m);
        }
    }
}

impl<T: UrlEncode> UrlEncode for &T {
    fn url_encode(&self, m: &mut HashMap<&'static str, String>) {
        T::url_encode(self, m);
    }
}

pub trait TupleRef<'a> {
    type Ref: 'a;

    fn as_ref(&'a self) -> Self::Ref;
}

impl<'a> TupleRef<'a> for Uuid {
    type Ref = &'a Uuid;

    fn as_ref(&'a self) -> Self::Ref {
        self
    }
}

impl<'a> TupleRef<'a> for String {
    type Ref = &'a String;

    fn as_ref(&'a self) -> Self::Ref {
        self
    }
}

impl<'a> TupleRef<'a> for () {
    type Ref = ();

    fn as_ref(&'a self) -> Self::Ref {
        ()
    }
}

impl<'a, T1: 'a> TupleRef<'a> for (T1,) {
    type Ref = (&'a T1,);

    fn as_ref(&'a self) -> Self::Ref {
        (&self.0,)
    }
}

impl<'a, T1: 'a, T2: 'a> TupleRef<'a> for (T1, T2) {
    type Ref = (&'a T1, &'a T2);

    fn as_ref(&'a self) -> Self::Ref {
        (&self.0, &self.1)
    }
}

impl<'a, T1: 'a, T2: 'a, T3: 'a> TupleRef<'a> for (T1, T2, T3) {
    type Ref = (&'a T1, &'a T2, &'a T3);

    fn as_ref(&'a self) -> Self::Ref {
        (&self.0, &self.1, &self.2)
    }
}