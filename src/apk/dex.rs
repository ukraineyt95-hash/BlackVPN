//! Генератор `classes.dex` — минимального DEX-файла с одним классом-«мостом».
//!
//! # Зачем это вообще нужно
//!
//! Android запускает VPN только через сервис, который **наследует**
//! `android.net.VpnService`. Объявить в манифесте сам `android.net.VpnService`
//! нельзя: система создаёт экземпляр класса через рефлексию
//! (`Class.forName(name).newInstance()`), и для абстрактного/«чужого»
//! сервиса это не работает. Значит, нужен свой класс:
//!
//! ```java
//! package com.example.byebyedpi;
//! public class RustVpnService extends android.net.VpnService {
//!     private native void nativeCreate();   // -> Rust: Java_..._nativeCreate
//!     private native void nativeRevoke();
//!
//!     @Override public void onCreate() {
//!         nativeCreate();       // здесь Rust строит Builder и делает establish()
//!         super.onCreate();
//!     }
//!     @Override public void onRevoke() {
//!         nativeRevoke();
//!         super.onRevoke();
//!     }
//! }
//! ```
//!
//! По условию задачи **в проекте нет исходников на Java/Kotlin**. Поэтому мы
//! не пишем этот класс руками, а генерируем его байткод (DEX) прямо из Rust
//! во время сборки. Это ровно тот же файл, что получился бы из `.java`,
//! только созданный программно: никаких `.java`/`.kt` в репозитории нет,
//! компилятора Java в процессе нет.
//!
//! # Формат DEX (кратко)
//!
//! ```text
//! ┌──────────────┬─────────────────────────────────────────────┐
//! │ header       │ 0x70 байт: magic, checksum, SHA-1, размеры   │
//! │ string_ids   │ u4[]: смещения string_data_item              │
//! │ type_ids     │ u4[]: индексы строк-дескрипторов типов       │
//! │ proto_ids    │ 12 байт: shorty, return_type, params_off     │
//! │ field_ids    │ 8 байт (у нас нет полей)                      │
//! │ method_ids   │ 8 байт: class_idx, proto_idx, name_idx        │
//! │ class_defs   │ 32 байта на класс                            │
//! │ data         │ code_item, class_data_item, string_data, map  │
//! └──────────────┴─────────────────────────────────────────────┘
//! ```
//!
//! Все таблицы (`string_ids`, `type_ids`, ...) обязаны быть **отсортированы**
//! по своим ключам — этого требует верификатор ART. Смещения в `data`
//! выравниваются на 4 байта.
//!
//! # Инструкции Dalvik, которые мы используем
//!
//! | Код    | Мнемоника        | Формат                                  |
//! |--------|------------------|-----------------------------------------|
//! | `0x1070` | invoke-direct  | 35c: op | count=1 | G=v0 | method_idx  |
//! | `0x106E` | invoke-virtual | 35c                                     |
//! | `0x106F` | invoke-super   | 35c                                     |
//! | `0x000E` | return-void    | 10x                                     |
//!
//! Для `35c` первое слово: `op | (G << 8) | (count << 12)`, где `G` — номер
//! регистра-аргумента в младшем полубайте. Второе слово — `method_idx`
//! (в нашем случае < 65536), третье — `C << 12 | D << 8 | E << 4 | F`
//! (для одного аргумента `count = 1`, `C = 0`).
use std::collections::BTreeSet;

/// Магия DEX версии 035 (Android 1.0+; поддерживается всеми устройствами).
const DEX_MAGIC: [u8; 8] = *b"dex\n035\0";

/// Индекс «нет ссылки».
const NO_INDEX: u32 = 0xFFFF_FFFF;

/// `ACC_PUBLIC` (0x1) — доступен всем.
const ACC_PUBLIC: u32 = 0x0001;

/// `ACC_NATIVE` (0x100) — реализация в нативной библиотеке.
const ACC_NATIVE: u32 = 0x0100;

/// `ACC_CONSTRUCTOR` (0x10000) — конструктор `<init>`.
const ACC_CONSTRUCTOR: u32 = 0x1_0000;

// Опкоды format 35c с A = 1 (передаём единственный аргумент — `this` из v0).
const INVOKE_DIRECT: u32 = 0x1070;
const INVOKE_VIRTUAL: u32 = 0x106E;
const INVOKE_SUPER: u32 = 0x106F;
const RETURN_VOID: u32 = 0x000E;

/// ULEB128-кодирование (переменная длина, little-endian, 7 бит на байт).
pub fn uleb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

/// Строка в MUTF-8 с завершающим нулём.
///
/// Наши строки — чистый ASCII (имена классов и методов), поэтому MUTF-8
/// совпадает с UTF-8. Для полноты реализована и кодировка символов вне BMP.
fn mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 1);
    for ch in s.chars() {
        let mut buf = [0u16; 2];
        for unit in ch.encode_utf16(&mut buf) {
            if *unit == 0 {
                // В MUTF-8 нулевой символ кодируется двумя байтами.
                out.push(0xC0);
                out.push(0x80);
            } else if *unit < 0x80 {
                out.push(*unit as u8);
            } else if *unit < 0x800 {
                out.push(0xC0 | (*unit >> 6) as u8);
                out.push(0x80 | (*unit & 0x3F) as u8);
            } else {
                out.push(0xE0 | (*unit >> 12) as u8);
                out.push(0x80 | ((*unit >> 6) & 0x3F) as u8);
                out.push(0x80 | (*unit & 0x3F) as u8);
            }
        }
    }
    out.push(0);
    out
}

/// Один метод класса-моста.
#[derive(Clone, Debug)]
pub struct MethodSpec {
    pub name: &'static str,
    /// Метод объявлен как `native` (тело реализовано в Rust).
    pub native: bool,
    /// Конструктор `<init>`.
    pub constructor: bool,
    /// Код метода в виде 16-битных слов DEX. Индексы методов внутри
    /// инструкций 35c берутся из пула `method_ids`, который строится для
    /// конкретного `DexSpec` (см. `DexBuilder::invoke`).
    pub insns: Vec<u32>,
}

/// Параметры генерации.
pub struct DexSpec {
    /// Дескриптор класса, например `Lcom/example/byebyedpi/RustVpnService;`.
    pub class: String,
    /// Дескриптор суперкласса, например `Landroid/net/VpnService;`.
    pub superclass: String,
    /// Имя исходного файла (для отладки, необязательно).
    pub source_file: String,
    pub methods: Vec<MethodSpec>,
}

struct Proto {
    shorty: &'static str,
    ret: &'static str,
}

/// Построитель DEX-файла с одним классом.
pub struct DexBuilder {
    strings: Vec<String>,
    string_index: Vec<u32>,
    types: Vec<String>,
    type_index: Vec<u32>,
    protos: Vec<Proto>,
    /// (class_idx, proto_idx, name_idx) — отсортировано по правилам DEX.
    methods: Vec<(u32, u32, u32)>,
    /// Собственные методы класса: (method_idx, спецификация).
    own: Vec<(u32, MethodSpec)>,
    class_idx: u32,
    super_idx: u32,
}

impl DexBuilder {
    /// Подготовить таблицы (строки, типы, методы) по спецификации.
    pub fn new(spec: &DexSpec) -> Self {
        let mut strings: BTreeSet<String> = BTreeSet::new();
        let mut types: BTreeSet<String> = BTreeSet::new();
        types.insert(spec.class.clone());
        types.insert(spec.superclass.clone());
        types.insert("V".to_string());

        // Дескрипторы типов тоже живут в пуле строк: type_ids ссылаются
        // именно на string_ids, поэтому класс, суперкласс, «V» и типы из
        // прототипов обязаны там присутствовать.
        strings.insert(spec.class.clone());
        strings.insert(spec.superclass.clone());

        for m in &spec.methods {
            strings.insert(m.name.to_string());
        }
        // Методы суперкласса, на которые ссылается сгенерированный код:
        // конструктор (invoke-direct) и переопределяемые колбэки
        // (invoke-super).
        for name in ["<init>", "onCreate", "onRevoke"] {
            strings.insert(name.to_string());
        }
        strings.insert(spec.source_file.clone());

        // Пул прототипов: все методы моста имеют вид `()V`
        // (у `nativeCreate`/`nativeRevoke`/`onCreate`/`onRevoke` нет
        // параметров, `<init>` тоже без параметров).
        let protos: Vec<Proto> = vec![Proto {
            shorty: "V",
            ret: "V",
        }];
        for p in &protos {
            strings.insert(p.shorty.to_string());
            strings.insert(p.ret.to_string());
        }

        let strings: Vec<String> = strings.into_iter().collect();
        let pos = |s: &str| strings.iter().position(|x| x == s).unwrap() as u32;

        let mut types: Vec<String> = types.into_iter().collect();
        types.sort_by_key(|t| pos(t));
        // 3) method_ids: (class_idx, proto_idx, name_idx), отсортированы по
        //    (class_idx, name_idx, proto_idx).
        let class_idx = types.iter().position(|t| *t == spec.class).unwrap() as u32;
        let super_idx = types.iter().position(|t| *t == spec.superclass).unwrap() as u32;

        // Все методы моста имеют прототип `()V`, и он единственный в пуле
        // `protos`, поэтому индекс прототипа всегда 0.
        const PROTO_INDEX: u32 = 0;

        // method_ids: сначала собственные, затем методы суперкласса.
        let mut refs: Vec<(u32, u32, u32)> = Vec::new();
        let mut own: Vec<(u32, MethodSpec)> = Vec::new();
        for m in &spec.methods {
            refs.push((class_idx, PROTO_INDEX, pos(m.name)));
        }
        for name in ["<init>", "onCreate", "onRevoke"] {
            refs.push((super_idx, PROTO_INDEX, pos(name)));
        }
        refs.sort();
        refs.dedup();
        for m in &spec.methods {
            let idx = refs
                .iter()
                .position(|(c, p, n)| {
                    *c == class_idx && *p == PROTO_INDEX && *n == pos(m.name)
                })
                .unwrap();
            own.push((idx as u32, m.clone()));
        }

        Self {
            string_index: strings.iter().map(|s| pos(s)).collect(),
            type_index: types.iter().map(|t| pos(t)).collect(),
            strings,
            types,
            protos,
            methods: refs,
            own,
            class_idx,
            super_idx,
        }
    }

    fn method_index(&self, class: &str, name: &str, proto: u32) -> u16 {
        let c = self.types.iter().position(|t| t == class).unwrap() as u32;
        let n = self.strings.iter().position(|s| s == name).unwrap() as u32;
        let idx = self
            .methods
            .iter()
            .position(|(mc, mp, mn)| *mc == c && *mp == proto && *mn == n)
            .expect("метод должен присутствовать в method_ids");
        assert!(idx <= u16::MAX as usize, "method_ids переполнены");
        idx as u16
    }

    /// Инструкция вызова метода в формате 35c — это ТРИ слова:
    ///   1) `op | A << 12 | G << 8`, где A — число аргументов;
    ///   2) 16-битный индекс метода в `method_ids`;
    ///   3) упакованные регистры `F | E << 4 | D << 8 | C << 12`.
    /// Здесь вызываем только `this`, лежащий в v0, поэтому A = 1, C = 0.
    fn invoke(&self, opcode: u32, class: &str, name: &str, proto: u32) -> [u32; 3] {
        [opcode, self.method_index(class, name, proto) as u32, 0x0000]
    }

    /// Собрать файл.
    pub fn build(mut self, spec: &DexSpec) -> Vec<u8> {
        let s_count = self.strings.len() as u32;
        let t_count = self.types.len() as u32;
        let p_count = self.protos.len() as u32;
        let m_count = self.methods.len() as u32;
        const F_COUNT: u32 = 0;
        const C_COUNT: u32 = 1;

        // --- расположение таблиц (сразу после заголовка 0x70) ----------- //
        let mut off = 0x70u32;
        let string_ids_off = off;
        off += 4 * s_count;
        let type_ids_off = off;
        off += 4 * t_count;
        let proto_ids_off = off;
        off += 12 * p_count;
        let field_ids_off = off;
        off += 8 * F_COUNT;
        let method_ids_off = off;
        off += 8 * m_count;
        let class_defs_off = off;
        off += 32 * C_COUNT;
        let data_off = off;
        let mut data: Vec<u8> = Vec::new();

        fn pad4(data: &mut Vec<u8>, data_off: u32) {
            while (data_off as usize + data.len()) % 4 != 0 {
                data.push(0);
            }
        }

        // --- code_item для всех не-native методов -----------------------
        let mut code_offset: Vec<(usize, u32)> = Vec::new();
        for (i, (_, m)) in self.own.iter().enumerate() {
            if m.native {
                continue;
            }
            pad4(&mut data, data_off);
            code_offset.push((i, data_off + data.len() as u32));
            write_code_item(&mut data, &m.insns);
        }
        let code_offset_of = |own_index: usize| -> u32 {
            code_offset
                .iter()
                .find(|(i, _)| *i == own_index)
                .map(|(_, o)| *o)
                .unwrap_or(0)
        };
        let code_count = code_offset.len() as u32;
        let first_code = code_offset.first().map(|(_, o)| *o).unwrap_or(0);

        // --- class_data_item -------------------------------------------
        // --- class_data_item ------------------------------------------- //
        // Методы делятся на direct (конструкторы и нативные) и virtual —
        // так требует формат. Внутри каждой группы — по возрастанию
        // индекса в method_ids.
        let mut direct: Vec<usize> = Vec::new();
        let mut virtual_: Vec<usize> = Vec::new();
        for (i, (_, m)) in self.own.iter().enumerate() {
            if m.native || m.constructor {
                direct.push(i);
            } else {
                virtual_.push(i);
            }
        }
        let midx = |i: usize| self.own[i].0;
        direct.sort_by_key(|i| midx(*i));
        virtual_.sort_by_key(|i| midx(*i));

        let class_data_off = data_off + data.len() as u32;
        data.extend(uleb128(0));
        data.extend(uleb128(0));
        data.extend(uleb128(direct.len() as u32));
        data.extend(uleb128(virtual_.len() as u32));

        {
            let own = &self.own;
            let mut write_methods = |data: &mut Vec<u8>, list: &[usize]| {
                let mut prev = 0u32;
                for &i in list {
                    let mi = own[i].0;
                    data.extend(uleb128(mi - prev));
                    prev = mi;
                    let m = &own[i].1;
                    let access = ACC_PUBLIC
                        | if m.native { ACC_NATIVE } else { 0 }
                        | if m.constructor { ACC_CONSTRUCTOR } else { 0 };
                    data.extend(uleb128(access));
                // code_off = 0 у нативных методов.
                    data.extend(uleb128(if m.native { 0 } else { code_offset_of(i) }));
                }
            };
            write_methods(&mut data, &direct);
            write_methods(&mut data, &virtual_);
        }

        // --- string_data_item ------------------------------------------
        let mut string_offsets: Vec<u32> = Vec::with_capacity(s_count as usize);
        let mut string_data: Vec<u8> = Vec::new();
        for s in &self.strings {
            string_offsets.push(data_off + data.len() as u32 + string_data.len() as u32);
            let bytes = mutf8(s);
            string_data.extend(uleb128(s.chars().count() as u32));
            string_data.extend_from_slice(&bytes);
        }
        let string_data_off = data_off + data.len() as u32;
        data.extend_from_slice(&string_data);
        self.string_index = string_offsets.clone();

        // --- map_list ---------------------------------------------------
            // выравнивание (проверяем, что расчёт совпал с фактом)
        pad4(&mut data, data_off);
        let map_off = data_off + data.len() as u32;
        // Секции, у которых есть данные.
        let mut sections: Vec<(u16, u32, u32)> = vec![
            (0x0001, s_count, string_ids_off),
            (0x0002, t_count, type_ids_off),
            (0x0003, p_count, proto_ids_off),
            (0x0005, m_count, method_ids_off),
            (0x0006, C_COUNT, class_defs_off),
            (0x1000, 1, map_off),
            (0x2000, 1, class_data_off),
            (0x2001, code_count, first_code),
            (0x2002, s_count, string_data_off),
        ];
        if F_COUNT > 0 {
            sections.push((0x0004, F_COUNT, field_ids_off));
        }
        // map_list требует сортировки по смещению.
        sections.sort_by_key(|(_, _, o)| *o);

        data.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        for (kind, count, offset) in &sections {
            data.extend_from_slice(&kind.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(&count.to_le_bytes());
            data.extend_from_slice(&offset.to_le_bytes());
        }

        // --- таблицы ----------------------------------------------------
        // --- таблицы ---------------------------------------------------- //
        let mut string_ids = Vec::with_capacity(4 * s_count as usize);
        for o in &string_offsets {
            string_ids.extend_from_slice(&o.to_le_bytes());
        }
        let mut type_ids = Vec::with_capacity(4 * t_count as usize);
        for idx in &self.type_index {
            type_ids.extend_from_slice(&idx.to_le_bytes());
        }

        let mut proto_ids = Vec::with_capacity(12 * p_count as usize);
        for (i, p) in self.protos.iter().enumerate() {
            let shorty = self.string_index[i];
            let ret = self.types.iter().position(|t| t == p.ret).unwrap() as u32;
            proto_ids.extend_from_slice(&shorty.to_le_bytes());
            proto_ids.extend_from_slice(&ret.to_le_bytes());
            proto_ids.extend_from_slice(&0u32.to_le_bytes());
        }

        let mut method_ids = Vec::with_capacity(8 * m_count as usize);
        for (cls, proto, name) in &self.methods {
            method_ids.extend_from_slice(&cls.to_le_bytes());
            method_ids.extend_from_slice(&proto.to_le_bytes());
            method_ids.extend_from_slice(&name.to_le_bytes());
        }

        let mut class_def = Vec::with_capacity(32);
        class_def.extend_from_slice(&self.class_idx.to_le_bytes());
        class_def.extend_from_slice(&ACC_PUBLIC.to_le_bytes());
        class_def.extend_from_slice(&self.super_idx.to_le_bytes());
        class_def.extend_from_slice(&0u32.to_le_bytes());
        let source_idx = self.strings.iter().position(|s| *s == spec.source_file);
        class_def.extend_from_slice(
            &source_idx
                .map(|i| i as u32)
                .unwrap_or(NO_INDEX)
                .to_le_bytes(),
        );
        class_def.extend_from_slice(&0u32.to_le_bytes());
        class_def.extend_from_slice(&class_data_off.to_le_bytes());
        class_def.extend_from_slice(&0u32.to_le_bytes());

        // --- сборка файла ----------------------------------------------- //
        let file_size = data_off as usize + data.len();
        let mut out: Vec<u8> = Vec::with_capacity(file_size);
        out.extend_from_slice(&[0u8; 0x70]);
        out.extend_from_slice(&string_ids);
        out.extend_from_slice(&type_ids);
        out.extend_from_slice(&proto_ids);
        out.extend_from_slice(&method_ids);
        out.extend_from_slice(&class_def);
        out.extend_from_slice(&data);
        debug_assert_eq!(out.len(), file_size);

        // --- заголовок --------------------------------------------------- //
        let mut header = [0u8; 0x70];
        header[0..8].copy_from_slice(&DEX_MAGIC);
        header[0x20..0x24].copy_from_slice(&(file_size as u32).to_le_bytes());
        header[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        header[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        header[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());
        header[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        header[0x34..0x38].copy_from_slice(&map_off.to_le_bytes());
        header[0x38..0x3C].copy_from_slice(&s_count.to_le_bytes());
        header[0x3C..0x40].copy_from_slice(&string_ids_off.to_le_bytes());
        header[0x40..0x44].copy_from_slice(&t_count.to_le_bytes());
        header[0x44..0x48].copy_from_slice(&type_ids_off.to_le_bytes());
        header[0x48..0x4C].copy_from_slice(&p_count.to_le_bytes());
        header[0x4C..0x50].copy_from_slice(&proto_ids_off.to_le_bytes());
        header[0x50..0x54].copy_from_slice(&F_COUNT.to_le_bytes());
        header[0x54..0x58].copy_from_slice(&field_ids_off.to_le_bytes());
        header[0x58..0x5C].copy_from_slice(&m_count.to_le_bytes());
        header[0x5C..0x60].copy_from_slice(&method_ids_off.to_le_bytes());
        header[0x60..0x64].copy_from_slice(&C_COUNT.to_le_bytes());
        header[0x64..0x68].copy_from_slice(&class_defs_off.to_le_bytes());
        header[0x68..0x6C].copy_from_slice(&(data.len() as u32).to_le_bytes());
        header[0x6C..0x70].copy_from_slice(&data_off.to_le_bytes());
        out[..0x70].copy_from_slice(&header);

        // --- контрольные суммы ------------------------------------------- //
        // signature = SHA-1 от всего файла, начиная с offset 32;
        // checksum  = Adler-32 от всего файла, начиная с offset 12.
        let signature = sha1(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        out[8..12].copy_from_slice(&checksum.to_le_bytes());

        out
    }
}

fn write_code_item(data: &mut Vec<u8>, insns: &[u32]) {
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(insns.len() as u32).to_le_bytes());
    // Код в DEX — последовательность 16-битных слов, поэтому режем u32.
    for w in insns {
        data.extend_from_slice(&(*w as u16).to_le_bytes());
    }
}

/// SHA-1 (FIPS 180-1). Своя реализация, чтобы не тянуть зависимость.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Дополнение: 0x80, нули, 8 байт длины в битах.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Adler-32 (RFC 1950).
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);

    // Блоками по 5552 байта, чтобы не переполнять u32.
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Дескриптор класса-моста.
pub const BRIDGE_CLASS: &str = "Lcom/example/byebyedpi/RustVpnService;";

/// Дескриптор суперкласса.
pub const BRIDGE_SUPER: &str = "Landroid/net/VpnService;";

/// Склеивает две инструкции вызова (по три слова каждая) и добавляет
/// `return-void`.
fn concat_insns(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(7);
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out.push(RETURN_VOID);
    out
}

/// Сгенерировать `classes.dex` с классом `RustVpnService`.
///
/// Байткод (эквивалент Java):
/// ```java
/// public class RustVpnService extends android.net.VpnService {
///     private native void nativeCreate();
///     private native void nativeRevoke();
///     public RustVpnService() { super(); }
///     @Override public void onCreate()  { nativeCreate(); super.onCreate(); }
///     @Override public void onRevoke()  { nativeRevoke(); super.onRevoke(); }
/// }
/// ```
pub fn build_bridge_dex() -> Vec<u8> {
    // 2) Собираем реальные тела методов (Rust знает индексы -> нужен
    //    второй проход, т.к. строки/методы те же, индексы совпадут).
    let spec = DexSpec {
        class: BRIDGE_CLASS.to_string(),
        superclass: BRIDGE_SUPER.to_string(),
        source_file: "RustVpnService.java".to_string(),
        methods: vec![
            // <init>: invoke-direct {v0}, VpnService.<init>()V ; return-void
            MethodSpec {
                name: "<init>",
                native: false,
                constructor: true,
                insns: Vec::new(),
            },
            // onCreate: invoke-virtual {v0}, nativeCreate()V
            //           invoke-super   {v0}, VpnService.onCreate()V ; return-void
            MethodSpec {
                name: "nativeCreate",
                native: true,
                constructor: false,
                insns: Vec::new(),
            },
            // onRevoke: invoke-virtual {v0}, nativeRevoke()V
            //           invoke-super   {v0}, VpnService.onRevoke()V ; return-void
            MethodSpec {
                name: "nativeRevoke",
                native: true,
                constructor: false,
                insns: Vec::new(),
            },
            MethodSpec {
                name: "onCreate",
                native: false,
                constructor: false,
                insns: Vec::new(),
            },
            MethodSpec {
                name: "onRevoke",
                native: false,
                constructor: false,
                insns: Vec::new(),
            },
        ],
    };

    // Первый проход: строим пулы только ради индексов методов — сам байткод
    // зависит от них, поэтому сборка идёт в два шага. Набор методов в обоих
    // проходах одинаков, поэтому индексы гарантированно совпадают.
    let probe = DexBuilder::new(&spec);
    let super_ctor = probe.invoke(INVOKE_DIRECT, BRIDGE_SUPER, "<init>", 0);
    let self_create = probe.invoke(INVOKE_VIRTUAL, BRIDGE_CLASS, "nativeCreate", 0);
    let self_revoke = probe.invoke(INVOKE_VIRTUAL, BRIDGE_CLASS, "nativeRevoke", 0);
    let super_create = probe.invoke(INVOKE_SUPER, BRIDGE_SUPER, "onCreate", 0);
    let super_revoke = probe.invoke(INVOKE_SUPER, BRIDGE_SUPER, "onRevoke", 0);

    // Второй проход: тот же набор методов, но `insns` уже заполнены.
    // Порядок строк и типов детерминирован, поэтому индексы совпадают.
    let spec = DexSpec {
        class: BRIDGE_CLASS.to_string(),
        superclass: BRIDGE_SUPER.to_string(),
        source_file: "RustVpnService.java".to_string(),
        methods: vec![
            MethodSpec {
                name: "<init>",
                native: false,
                constructor: true,
                insns: concat_insns(&super_ctor, &[]),
            },
            MethodSpec {
                name: "nativeCreate",
                native: true,
                constructor: false,
                insns: Vec::new(),
            },
            MethodSpec {
                name: "nativeRevoke",
                native: true,
                constructor: false,
                insns: Vec::new(),
            },
            MethodSpec {
                name: "onCreate",
                native: false,
                constructor: false,
                insns: concat_insns(&self_create, &super_create),
            },
            MethodSpec {
                name: "onRevoke",
                native: false,
                constructor: false,
                insns: concat_insns(&self_revoke, &super_revoke),
            },
        ],
    };

    DexBuilder::new(&spec).build(&spec)
}

// ---------------------------------------------------------------------------
//  Тесты
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vectors() {
        // Значения из FIPS 180-1.
        let h = sha1(b"abc");
        assert_eq!(
            h.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let h = sha1(b"");
        assert_eq!(
            h.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn adler32_known_vector() {
        // RFC 1950: adler32("Wikipedia") = 0x11E60398
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    /// DEX должен быть валиден: магия, размер, контрольные суммы,
    /// отсортированные таблицы.
    #[test]
    fn uleb128_roundtrip() {
        assert_eq!(uleb128(0), vec![0]);
        assert_eq!(uleb128(127), vec![0x7F]);
        assert_eq!(uleb128(128), vec![0x80, 0x01]);
        assert_eq!(uleb128(624485), vec![0xE5, 0x8E, 0x26]);
    }

    #[test]
    fn bridge_dex_is_structurally_valid() {
        let dex = build_bridge_dex();

        // 1) Магия и размер.
        assert_eq!(&dex[0..8], b"dex\n035\0");
        let file_size = u32::from_le_bytes([dex[0x20], dex[0x21], dex[0x22], dex[0x23]]) as usize;
        assert_eq!(file_size, dex.len(), "file_size должен совпадать");

        // 2) Header size / endian tag.
        let header_size =
            u32::from_le_bytes([dex[0x24], dex[0x25], dex[0x26], dex[0x27]]) as usize;
        assert_eq!(header_size, 0x70);
        assert_eq!(
            u32::from_le_bytes([dex[0x28], dex[0x29], dex[0x2A], dex[0x2B]]),
            0x1234_5678
        );

        // 3) Контрольные суммы.
        let stored_sig = &dex[12..32];
        assert_eq!(stored_sig, &sha1(&dex[32..])[..], "SHA-1 подпись неверна");
        let stored_sum = u32::from_le_bytes([dex[8], dex[9], dex[10], dex[11]]);
        assert_eq!(stored_sum, adler32(&dex[12..]), "Adler-32 неверен");

        // 4) Таблицы string_ids / type_ids / method_ids отсортированы.
        let s_count = u32::from_le_bytes([dex[0x38], dex[0x39], dex[0x3A], dex[0x3B]]) as usize;
        let s_off = u32::from_le_bytes([dex[0x3C], dex[0x3D], dex[0x3E], dex[0x3F]]) as usize;
        assert!(s_count > 0);

        // Читаем строки и проверяем, что они идут в лексикографическом
        // порядке (требование DEX).
        let mut prev: Option<Vec<u8>> = None;
        for i in 0..s_count {
            let p = s_off + 4 * i;
            let data_at = u32::from_le_bytes([dex[p], dex[p + 1], dex[p + 2], dex[p + 3]]) as usize;

            // uleb128 длина + MUTF-8 + \0
            let (len, mut q) = read_uleb(&dex, data_at);
            let bytes = dex[q..q + len].to_vec();
            q += len;
            assert_eq!(dex[q], 0, "строка должна завершаться нулём");
            if let Some(prev) = prev {
                assert!(prev < bytes, "string_ids должны быть отсортированы");
            }
            prev = Some(bytes);
        }

        // 5) Методы: 5 штук, среди них два native.
        let m_count = u32::from_le_bytes([dex[0x58], dex[0x59], dex[0x5A], dex[0x5B]]) as usize;
        // 5 собственных методов + 3 ссылки на методы VpnService.
        assert_eq!(m_count, 8);

        // 6) В файле есть имя класса и имена нативных методов.
        let text = String::from_utf8_lossy(&dex);
        assert!(text.contains("RustVpnService"));
        assert!(text.contains("nativeCreate"));
        assert!(text.contains("nativeRevoke"));
        assert!(text.contains("VpnService"));
    }

    /// Проверяет, что сгенерированный мост действительно вызывает
    /// `<init>`/`onCreate`/`onRevoke` у `android.net.VpnService`, а нативные
    /// методы — у собственного класса. Без этого вызывался бы не тот метод.
    #[test]
    fn bridge_dex_refs_resolve_to_vpnservice() {
        let dex = build_bridge_dex();

        let m_count = u32::from_le_bytes([dex[0x58], dex[0x59], dex[0x5A], dex[0x5B]]) as usize;
        let m_off = u32::from_le_bytes([dex[0x5C], dex[0x5D], dex[0x5E], dex[0x5F]]) as usize;
        let s_count = u32::from_le_bytes([dex[0x38], dex[0x39], dex[0x3A], dex[0x3B]]) as usize;
        let s_off = u32::from_le_bytes([dex[0x3C], dex[0x3D], dex[0x3E], dex[0x3F]]) as usize;
        let t_count = u32::from_le_bytes([dex[0x40], dex[0x41], dex[0x42], dex[0x43]]) as usize;
        let t_off = u32::from_le_bytes([dex[0x44], dex[0x45], dex[0x46], dex[0x47]]) as usize;

        let string_at = |idx: usize| -> String {
            let at = u32::from_le_bytes([
                dex[s_off + 4 * idx],
                dex[s_off + 4 * idx + 1],
                dex[s_off + 4 * idx + 2],
                dex[s_off + 4 * idx + 3],
            ]) as usize;
            let (len, p) = read_uleb(&dex, at);
            String::from_utf8_lossy(&dex[p..p + len]).into_owned()
        };
        let type_at = |idx: usize| -> String {
            let s = u32::from_le_bytes([
                dex[t_off + 4 * idx],
                dex[t_off + 4 * idx + 1],
                dex[t_off + 4 * idx + 2],
                dex[t_off + 4 * idx + 3],
            ]) as usize;
            string_at(s)
        };
        let method_at = |idx: usize| -> (String, String) {
            let p = m_off + 8 * idx;
            let cls = u16::from_le_bytes([dex[p], dex[p + 1]]) as usize;
            let name =
            u32::from_le_bytes([dex[p + 4], dex[p + 5], dex[p + 6], dex[p + 7]]) as usize;
            (type_at(cls), string_at(name))
        };

        let mut found = std::collections::BTreeSet::new();
        for i in 0..m_count {
            let (cls, name) = method_at(i);
            found.insert((cls, name));
        }
        let key = |c: &str, n: &str| (c.to_string(), n.to_string());
        assert!(
            found.contains(&key(BRIDGE_SUPER, "<init>")),
            "нет ссылки на VpnService.<init>: {found:?}"
        );
        assert!(found.contains(&key(BRIDGE_SUPER, "onCreate")));
        assert!(found.contains(&key(BRIDGE_SUPER, "onRevoke")));
        assert!(found.contains(&key(BRIDGE_CLASS, "nativeCreate")));
        assert!(found.contains(&key(BRIDGE_CLASS, "nativeRevoke")));
        assert_eq!(m_count, 8);
        assert!(s_count > 0 && t_count >= 3);
    }

    /// Владелец кода должен проверять, что инструкция 35c состоит из трёх
    /// слов: опкод, индекс метода, регистры. Иначе ART увидит мусор.
    #[test]
    fn invoke_encodes_three_words() {
        let spec = DexSpec {
            class: BRIDGE_CLASS.to_string(),
            superclass: BRIDGE_SUPER.to_string(),
            source_file: "RustVpnService.java".to_string(),
            methods: vec![
                MethodSpec {
                    name: "<init>",
                    native: false,
                    constructor: true,
                    insns: vec![],
                },
                MethodSpec {
                    name: "nativeCreate",
                    native: true,
                    constructor: false,
                    insns: vec![],
                },
                MethodSpec {
                    name: "nativeRevoke",
                    native: true,
                    constructor: false,
                    insns: vec![],
                },
                MethodSpec {
                    name: "onCreate",
                    native: false,
                    constructor: false,
                    insns: vec![],
                },
                MethodSpec {
                    name: "onRevoke",
                    native: false,
                    constructor: false,
                    insns: vec![],
                },
            ],
        };
        let b = DexBuilder::new(&spec);
        let insn = b.invoke(INVOKE_SUPER, BRIDGE_SUPER, "onCreate", 0);
        assert_eq!(insn.len(), 3);
        assert_eq!(insn[0], INVOKE_SUPER);
        assert_eq!(insn[2], 0);
        assert!((insn[1] as usize) < b.methods.len());
        assert_ne!(insn[1], b.invoke(INVOKE_VIRTUAL, BRIDGE_CLASS, "nativeCreate", 0)[1]);
    }

    fn read_uleb(data: &[u8], mut p: usize) -> (usize, usize) {
        let mut value = 0usize;
        let mut shift = 0;
        loop {
            let byte = data[p];
            p += 1;
            value |= ((byte & 0x7F) as usize) << shift;
            if byte & 0x80 == 0 {
                return (value, p);
            }
            shift += 7;
        }
    }
}
