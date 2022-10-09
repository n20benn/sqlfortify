import sys

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: derive_cockroach_tokens.py <infilepath>")
    
    filepath = sys.argv[1]

    with open(filepath, 'r') as infile:
        lines = infile.readlines()

    literals = list()
    seen = set()

    for line in lines:
        words = [val.strip() for val in line.split(' ')]
        for word in words:
            if len(word) > 1 and word[0] == "'" and word[-1] == "'":
                word = word[1:-1]
                if not word in seen:
                    literals.append(word)
                    seen.add(word)


    enum_names = []
    for literal in literals:
        if len(literal) > 1:
            enum_name = literal[0] + literal[1:].lower()

            i = enum_name.find('_')
            while i >= 0:
                enum_name = enum_name[:i] + enum_name[i+1:i+2].upper() + enum_name[i+2:]
                i = enum_name.find('_')
        else:
            enum_name = literal

        enum_names.append(enum_name)

    # Now to output in the format we desire: rust code

    print("pub enum Keyword {")
    for enum_name in enum_names:
        print(f"\t{enum_name},")
    print("}")

    print("")
    print("")

    print("static KEYWORDS:phf::Map<&'static str, CockroachToken> = phf_map! {")
    for enum_name,literal in zip(enum_names, literals):
        print(f"\t\"{literal}\" => CockroachToken::Keyword(Keyword::{enum_name}),")
    print("}")





if __name__ == '__main__':
    main()