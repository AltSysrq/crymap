//-
// Copyright (c) 2020, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

// This file is include!()d into `syntax.rs`.

macro_rules! syntax_rule {
    (#[$($whole_struct_mod:tt)*]
     struct $struct_name:ident<$lt:lifetime> {
         $(#[$($field_mod:tt)*]
           #[$($field_form:tt)*]
           $field_name:ident: $field_type:ty,)+
    }) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $struct_name<$lt> {
            $(pub $field_name: $field_type,)+
        }

        impl<'a> $struct_name<'a> {
            pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], $struct_name<'a>> {
                apply_nom_modifiers!(
                    [$($whole_struct_mod)*],
                    map(sequence::tuple((
                        $(apply_nom_modifiers!(
                            [$($field_mod)*],
                            generate_field_form!(
                                $field_type, $($field_form)*)),)+
                    )), |($($field_name,)*)| $struct_name {
                        $($field_name,)*
                    }))(i)
            }

            pub fn write_to(&mut self, lex: &mut LexWriter<impl Write>)
                            -> io::Result<()> {
                let this = self;
                apply_write_modifiers!([$($whole_struct_mod)*], lex, this, {
                    $(let $field_name = &mut this.$field_name;
                      apply_write_modifiers!(
                          [$($field_mod)*], lex, $field_name, {
                              generate_field_writer!(
                                  $($field_form)*, lex, $field_name);
                          });
                    )*
                });
                Ok(())
            }
        }
    };

    (#[$($whole_enum_mod:tt)*]
     enum $enum_name:ident<$lt:lifetime> {
         $(#[$($case_mod:tt)*]
           #[$($case_form:tt)*]
           $case_name:ident($case_type:ty),)+
    }) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $enum_name<$lt> {
            $($case_name($case_type),)+
        }

        impl<'a> $enum_name<'a> {
            pub fn parse(i: &'a [u8]) -> IResult<&'a [u8], $enum_name<'a>> {
                apply_nom_modifiers!(
                    [$($whole_enum_mod)*],
                    alt((
                        $(map(
                            apply_nom_modifiers!(
                                [$($case_mod)*],
                                generate_field_form!(
                                    $case_type, $($case_form)*)),
                            $enum_name::$case_name),)+
                    )))(i)
            }

            pub fn write_to(&mut self, lex: &mut LexWriter<impl Write>)
                            -> io::Result<()> {
                let this = self;
                apply_write_modifiers!([$($whole_enum_mod)*], lex, this, {
                    match this {
                        $(&mut $enum_name::$case_name(ref mut inner) => {
                            apply_write_modifiers!(
                                [$($case_mod)*], lex, inner, {
                                    generate_field_writer!(
                                        $($case_form)*, lex, inner);
                                });
                        })+
                    }
                });
                Ok(())
            }
        }
    };
}

macro_rules! apply_nom_modifiers {
    ([], $inner:expr) => { $inner };
    ([prefix($prefix:expr) $($rest:tt)*], $inner:expr) => {
        sequence::preceded(
            kw($prefix),
            apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([suffix($suffix:expr) $($rest:tt)*], $inner:expr) => {
        sequence::terminated(
            apply_nom_modifiers!([$($rest)*], $inner),
            kw($suffix))
    };
    ([surrounded($prefix:expr, $suffix:expr) $($rest:tt)*], $inner:expr) => {
        sequence::delimited(
            kw($prefix),
            apply_nom_modifiers!([$($rest)*], $inner),
            kw($suffix))
    };
    ([maybe_surrounded($prefix:expr, $suffix:expr) $($rest:tt)*],
     $inner:expr) => {
        alt((
            sequence::delimited(
                kw($prefix),
                apply_nom_modifiers!([$($rest)*], $inner),
                kw($suffix)),
            apply_nom_modifiers!([$($rest)*], $inner),
        ))
    };
    ([0*($sep:expr) $($rest:tt)*], $inner:expr) => {
        multi::separated_list(
            kw($sep),
            apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([0* $($rest:tt)*], $inner:expr) => {
        multi::many0(
            apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([1*($sep:expr) $($rest:tt)*], $inner:expr) => {
        multi::separated_nonempty_list(
            kw($sep),
            apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([1* $($rest:tt)*], $inner:expr) => {
        multi::many1(
            apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([marked_opt($marker:expr) $($rest:tt)*], $inner:expr) => {
        alt((
            map(kw($marker), |_| None),
            map(apply_nom_modifiers!([$($rest)*], $inner), Some),
        ))
    };
    ([nil $($rest:tt)*], $inner:expr) => {
        alt((
            map(kw(b"NIL"), |_| None),
            map(apply_nom_modifiers!([$($rest)*], $inner), Some),
        ))
    };
    ([nil_if_empty $($rest:tt)*], $inner:expr) => {
        alt((
            map(kw(b"NIL"), |_| Default::default()),
            apply_nom_modifiers!([$($rest)*], $inner),
        ))
    };
    ([opt $($rest:tt)*], $inner:expr) => {
        opt(apply_nom_modifiers!([$($rest)*], $inner))
    };
    ([box $($rest:tt)*], $inner:expr) => {
        map(apply_nom_modifiers!([$($rest)*], $inner), Box::new)
    };
}

macro_rules! generate_field_form {
    ($ty:ty,
     primitive($writer_method:ident, $syntax_function:ident)) => {
        $syntax_function
    };
    ($ty:ty, delegate) => {
        <$ty>::parse
    };
    ($_ty:ty, delegate($ty:ty)) => {
        <$ty>::parse
    };
    ($_ty:ty, tag($tag:expr)) => {
        map(kw($tag), |_| ())
    };
    ($_ty:ty, cond($tag:expr)) => {
        map(opt(kw($tag)), |v| v.is_some())
    };
    ($_ty:ty, phantom) => {
        |i| Ok((i, PhantomData))
    };
}

macro_rules! apply_write_modifiers {
    ([], $lex:expr, $var:ident, $inner:expr) => { $inner };
    ([prefix($prefix:expr) $($rest:tt)*], $lex:expr,
     $var:ident, $inner:expr) => {
        $lex.verbatim($prefix)?;
        apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
    };
    ([suffix($suffix:expr) $($rest:tt)*], $lex:expr,
     $var:ident, $inner:expr) => {
        apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        $lex.verbatim($suffix)?;
    };
    ([surrounded($prefix:expr, $suffix:expr) $($rest:tt)*], $lex:expr,
     $var:ident, $inner:expr) => {
        $lex.verbatim($prefix)?;
        apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        $lex.verbatim($suffix)?;
    };
    ([maybe_surrounded($prefix:expr, $suffix:expr) $($rest:tt)*], $lex:expr,
     $var:ident, $inner:expr) => {
        $lex.verbatim($prefix)?;
        apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        $lex.verbatim($suffix)?;
    };
    ([0*($sep:expr) $($rest:tt)*], $lex:expr, $var:ident, $inner:expr) => {
        let mut first = true;
        for $var in $var {
            if !first {
                $lex.verbatim($sep)?;
            }
            first = false;
            apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        }
    };
    ([0* $($rest:tt)*], $lex:expr, $var:ident, $inner:expr) => {
        for $var in $var {
            apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        }
    };
    ([1*($sep:expr) $($rest:tt)*], $lex:expr, $var:ident, $inner:expr) => {
        let mut first = true;
        for $var in $var {
            if !first {
                $lex.verbatim($sep)?;
            }
            first = false;
            apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        }
    };
    ([1* $($rest:tt)*], $lex:expr, $var:ident, $inner:expr) => {
        for $var in $var {
            apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        }
    };
    ([marked_opt($marker:expr) $($rest:tt)*],
     $lex:expr, $var:ident, $inner:expr) => {
        match $var {
            &mut None => $lex.verbatim($marker)?,
            &mut Some(ref mut $var) => {
                apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
            }
        }
    };
    ([nil $($rest:tt)*],
     $lex:expr, $var:ident, $inner:expr) => {
        match $var {
            &mut None => $lex.nil()?,
            &mut Some(ref mut $var) => {
                apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
            }
        }
    };
    ([nil_if_empty $($rest:tt)*],
     $lex:expr, $var:ident, $inner:expr) => {
        if $var.is_empty() {
            $lex.nil()?;
        } else {
            apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
        }
    };
    ([opt $($rest:tt)*],
     $lex:expr, $var:ident, $inner:expr) => {
        match $var {
            &mut None => (),
            &mut Some(ref mut $var) => {
                apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
            }
        }
    };
    ([box $($rest:tt)*],
     $lex:expr, $var:ident, $inner:expr) => {
        let $var = &mut **$var;
        apply_write_modifiers!([$($rest)*], $lex, $var, $inner);
    }
}

macro_rules! generate_field_writer {
    (primitive($writer_method:ident, $syntax_function:ident),
     $lex:expr, $value:expr) => {
        $lex.$writer_method($value)?;
    };
    (delegate, $lex:expr, $value:expr) => {
        $value.write_to($lex)?;
    };
    (delegate($ty:ty), $lex:expr, $value:expr) => {
        $value.write_to($lex)?;
    };
    (tag($tag:expr), $lex:expr, $_value:expr) => {
        let _value = $_value;
        $lex.verbatim($tag)?;
    };
    (cond($tag:expr), $lex:expr, $value:expr) => {
        if *$value {
            $lex.verbatim($tag)?;
        }
    };
    (phantom, $_lex:expr, $_value:expr) => {
        let _value = $_value;
    };
}

macro_rules! simple_enum {
    (enum $name:ident {
         $($case_name:ident($case_repr:expr),)+
    }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($case_name,)+
        }

        impl $name {
            pub fn parse(i: &[u8]) -> IResult<&[u8], $name> {
                alt((
                    $(map(kw($case_repr), |_| $name::$case_name),)+
                ))(i)
            }

            pub fn write_to(&self, lex: &mut LexWriter<impl Write>)
                            -> io::Result<()> {
                lex.verbatim(match *self {
                    $($name::$case_name => $case_repr,)+
                })
            }
        }
    }
}

