#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

using Elf_Ehdr = Elf64_Ehdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Phdr = Elf64_Phdr;
using Elf_Sym = Elf64_Sym;
using Elf_Rel = Elf64_Rel;

Elf_Shdr *getSectionHeader(char *head, Elf_Ehdr *ehdr, int index)
{
	return reinterpret_cast<Elf_Shdr *>(head + ehdr->e_shoff + ehdr->e_shentsize * index);
}

// ELFファイルのヘッダーを検証します
void validationElfHeader(Elf_Ehdr *ehdr)
{
	// ELFファイルかどうかを確認します
	if (!((ehdr->e_ident[EI_MAG0] == ELFMAG0) && (ehdr->e_ident[EI_MAG1] == ELFMAG1) &&
		  (ehdr->e_ident[EI_MAG2] == ELFMAG2) && (ehdr->e_ident[EI_MAG3] == ELFMAG3)))
		throw std::runtime_error("This is not an ELF file.\n");

	// ELFファイルが64ビットかどうかを確認します
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		throw std::runtime_error("Unknown class. (" + std::to_string(static_cast<int>(ehdr->e_ident[EI_CLASS])) + ")\n");

	// ELFファイルがリトルエンディアンかどうかを確認します
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		throw std::runtime_error("Unknown endian. (" + std::to_string(static_cast<int>(ehdr->e_ident[EI_DATA])) + ")\n");
}

Elf_Shdr *printSections(char *head, Elf_Ehdr *ehdr, Elf_Shdr *shstr)
{
	// 各セクションの情報を表示します
	std::cout << "Sections:" << std::endl;

	Elf_Shdr *symstr = nullptr;

	// セクションヘッダーの数だけ繰り返します
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		// セクションヘッダーを取得します
		// 		先頭 + セクションヘッダーのオフセット + セクションヘッダーのサイズ * セクションヘッダーのインデックス
		Elf_Shdr *shdr = getSectionHeader(head, ehdr, i);

		// セクションヘッダーの名前を取得します
		// 		先頭 + セクションヘッダー文字列テーブルのオフセット + セクションヘッダーの名前のオフセット
		char *sname = head + shstr->sh_offset + shdr->sh_name;

		// セクションヘッダーの情報を表示します
		std::cout << "\t[" << i << "]\t" << sname << std::endl;

		// セクションヘッダーの名前が".strtab"の場合、セクションヘッダーをstrに保存します
		// 		これは、セクションヘッダー文字列テーブルを指すセクションヘッダーです
		//		あとで、シンボルの名前を取得するために使います
		if (!strcmp(sname, ".strtab"))
			symstr = shdr;
	}

	return symstr;
}

void printSegments(char *head, Elf_Ehdr *ehdr, Elf_Shdr *shstr)
{
	// 各セグメントの情報を表示します
	std::cout << "Segments:" << std::endl;
	// プログラムヘッダーの数だけ繰り返します
	for (int i = 0; i < ehdr->e_phnum; i++)
	{
		// プログラムヘッダーを取得します
		// 		先頭 + プログラムヘッダーのオフセット + プログラムヘッダーのサイズ * プログラムヘッダーのインデックス
		Elf_Phdr *phdr = reinterpret_cast<Elf_Phdr *>(head + ehdr->e_phoff + ehdr->e_phentsize * i);
		std::cout << "\t[" << i << "]\t";

		// iセグメントとjセクションの位置とサイズを比較し、そのセクションがセグメント中に含まれてることがわかれば、そのセクションの名前を表示します
		for (int j = 0; j < ehdr->e_shnum; j++)
		{
			// セクションヘッダーを取得します
			// 		先頭 + セクションヘッダーのオフセット + セクションヘッダーのサイズ * セクションヘッダーのインデックス
			Elf_Shdr *shdr = getSectionHeader(head, ehdr, j);

			// セクションヘッダーのサイズ
			int size;

			// セクションがBSSセクションの場合、サイズは0です
			if (shdr->sh_type != SHT_NOBITS)
				size = shdr->sh_size;
			else
				size = 0;

			// セクションのオフセットがセグメントのオフセットより小さい場合、セクションはセグメントに含まれていません
			// 		これは、セクションがセグメントの前にあることを意味します
			if (shdr->sh_offset < phdr->p_offset)
				continue;

			// セクションのオフセット + セクションのサイズがセグメントのオフセット + セグメントのサイズより大きい場合、セクションはセグメントに含まれていません
			// 		これは、セクションがセグメントの後ろにあることを意味します
			if (shdr->sh_offset + size > phdr->p_offset + phdr->p_filesz)
				continue;

			// セクションの名前を取得します
			// 		先頭 + セクションヘッダー文字列テーブルのオフセット + セクションヘッダーの名前のオフセット
			char *sname = head + shstr->sh_offset + shdr->sh_name;

			// セクションの名前を表示します
			std::cout << sname << " ";
		}

		std::cout << "\n";
	}
}

Elf_Shdr *printSymbols(char *head, Elf_Ehdr *ehdr, Elf_Shdr *symstr)
{
	// 各シンボルの情報を表示します
	std::cout << "Symbols:" << std::endl;

	Elf_Shdr *sym = nullptr;

	// セクションヘッダーの数だけ繰り返します
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		// セクションヘッダーを取得します
		// 		先頭 + セクションヘッダーのオフセット + セクションヘッダーのサイズ * セクションヘッダーのインデックス
		// リロケーションの情報を表示する際に使うため、セクションヘッダー(シンボルテーブル)を保存します
		// 		リロケーションエントリに登録されているシンボルを取得する際に参照します
		Elf_Shdr *shdr = getSectionHeader(head, ehdr, i);

		// iセクションがシンボルテーブルでない場合、次のセクションへ
		if (shdr->sh_type != SHT_SYMTAB)
			continue;

		sym = shdr;

		// シンボルテーブルの数だけ繰り返します
		for (long unsigned int j = 0; j < sym->sh_size / sym->sh_entsize; j++)
		{
			// シンボルを取得します
			// 		先頭 + シンボルテーブルのオフセット + シンボルテーブルのサイズ * シンボルテーブルのインデックス
			Elf_Sym *symp = reinterpret_cast<Elf_Sym *>(head + sym->sh_offset + sym->sh_entsize * j);

			// シンボルの名前がない場合、次のシンボルへ
			if (!symp->st_name)
				continue;

			// シンボルの情報を表示します
			// 		ELF64_ST_TYPEは、st_infoフィールドの下位4ビットを取得するマクロです
			//		下位4ビットは、シンボルの種類を表します（STT_NOTYPE, STT_OBJECT(変数名), STT_FUNC(関数名)など）
			// std::coutはnull文字を検出するまでメモリを読み込む
			//		シンボルの名前はnull文字で終わっているため、std::coutでシンボルの名前を表示することができます
			//		null文字がない場合、std::coutはメモリを読み込み続けるため、セグメンテーションフォルトが発生します
			//		また変数は、coutは変数を自動的に文字列に変換し、その際にnull文字を挿入するので問題ない
			std::cout << "\t[" << j << "]\t" << static_cast<int>(ELF64_ST_TYPE(symp->st_info)) << "\t"
					  << symp->st_size << "\t" << head + symstr->sh_offset + symp->st_name << std::endl;
		}
		break;
	}

	return sym;
}

void printRelocations(char *head, Elf_Ehdr *ehdr, Elf_Shdr *symstr, Elf_Shdr *sym)
{
	// 各リロケーションの情報を表示します
	std::cout << "Relocations:" << std::endl;

	// セクションヘッダーの数だけ繰り返します
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		// セクションヘッダーを取得します
		// 		先頭 + セクションヘッダーのオフセット + セクションヘッダーのサイズ * セクションヘッダーのインデックス
		Elf_Shdr *rel = getSectionHeader(head, ehdr, i);

		// iセクションがリロケーションテーブルでない場合、次のセクションへ
		if ((rel->sh_type != SHT_REL) && (rel->sh_type != SHT_RELA))
			continue;

		// リロケーションテーブルの数だけ繰り返します
		for (long unsigned int j = 0; j < rel->sh_size / rel->sh_entsize; j++)
		{
			// リロケーションを取得します
			// 		先頭 + リロケーションテーブルのオフセット + リロケーションテーブルのサイズ * リロケーションテーブルのインデックス
			Elf_Rel *relp = reinterpret_cast<Elf_Rel *>(head + rel->sh_offset + rel->sh_entsize * j);

			// リロケーションエントリに登録されているシンボルをシンボルテーブル（sym）から取得します
			// 		先頭 + シンボルテーブルのオフセット + シンボルテーブルのサイズ * リロケーションのシンボルのインデックス
			//				ELF64_R_SYMは、シンボルテーブル中での対象シンボルのインデックスを取得するマクロです
			Elf_Sym *symp = reinterpret_cast<Elf_Sym *>(head + sym->sh_offset + (sym->sh_entsize * ELF64_R_SYM(relp->r_info)));

			// リロケーションのシンボルがない場合、次のリロケーションへ
			if (!symp->st_name)
				continue;

			// リロケーションの情報を表示します
			std::cout << "\t[" << j << "]\t" << ELF64_R_SYM(relp->r_info) << "\t"
					  << head + symstr->sh_offset + symp->st_name << std::endl;
		}
	}
}

// ファイルの内容を解析し、ELFファイルの情報を表示します
static int elfdump(char *head)
{
	try
	{
		// ELFファイルのヘッダー
		// 		ファイルの内容の先頭をELFヘッダーにキャストします
		// 		ポインタ型同士のキャストはreinterpret_castを使います
		Elf_Ehdr *ehdr = reinterpret_cast<Elf_Ehdr *>(head);

		// ELFファイルかどうかを確認します
		validationElfHeader(ehdr);

		// 可変長のセクション名を格納するセクションヘッダを取得
		// 		先頭 + セクションヘッダーのオフセット + セクションヘッダーのサイズ * セクションヘッダー文字列テーブルのインデックス
		Elf_Shdr *shstr = reinterpret_cast<Elf_Shdr *>(head + ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shstrndx);

		// 可変長のシンボル名を格納するセクションヘッダーを格納する変数
		// 表示させながら取得
		Elf_Shdr *symstr = printSections(head, ehdr, shstr);

		printSegments(head, ehdr, shstr);

		// シンボルテーブルを格納する変数
		Elf_Shdr *sym = printSymbols(head, ehdr, symstr);

		printRelocations(head, ehdr, symstr, sym);
	}
	catch (const std::exception &e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}

// メイン関数では、コマンドライン引数として指定されたELFファイルを開き、その内容をメモリにマッピングします
// マッピングされた内容はelfdump関数に渡され、ELFファイルの情報が表示されます
// マッピングが終わった後、メモリから解放し、ファイルを閉じます
int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
		return 1;
	}

	// 指定されたファイルを読み込み専用で開きます
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0)
	{
		std::cerr << "Failed to open file: " << argv[1] << std::endl;
		exit(1);
	}

	// ファイルの情報を取得します
	// 		ファイルの情報は、stat構造体に格納されます
	// 		stat構造体は、ファイルの情報を格納する構造体です
	struct stat sb;
	if (fstat(fd, &sb) == -1)
	{
		std::cerr << "Failed to get file information" << std::endl;
		close(fd);
		return 1;
	}

	// ファイルの内容をメモリにマッピングします
	// 		マッピングされた内容は、headに格納されます
	//			NULLとは、マッピングされたメモリの先頭アドレスを指定するための引数です
	// 			PROT_READとは、マッピングされたメモリを読み込み専用にするためのフラグです
	// 			MAP_SHAREDとは、マッピングされたメモリを他のプロセスと共有するためのフラグです
	//			char *にしておくと、strcmpなどの文字列操作ができて便利です
	char *head = reinterpret_cast<char *>(mmap(nullptr, sb.st_size, PROT_READ, MAP_SHARED, fd, 0));
	if (head == MAP_FAILED)
	{
		std::cerr << "Failed to map file into memory" << std::endl;
		close(fd);
		return 1;
	}

	// ELFファイルの情報を表示します
	try
	{
		elfdump(head);
	}
	// 例外が発生した場合、例外の内容を表示します
	catch (const std::exception &e)
	{
		// 例外の内容は、what()メソッドで取得できます
		std::cerr << "Failed to dump ELF file: " << e.what() << std::endl;
		munmap(head, sb.st_size);
		close(fd);
		return 1;
	}

	// メモリからファイルの内容を解放します
	// 		解放するメモリの先頭アドレスとサイズを指定します
	munmap(head, sb.st_size);

	// ファイルを閉じます
	close(fd);

	return 0;
}
