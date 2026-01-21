#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>

// מבנה לניהול קובץ ELF פתוח וממופה
typedef struct {
    int fd;
    void *map_start;
    off_t file_size;
    char filename[256];
} elf_file;

// משתנים גלובליים
int debug_mode = 0;
elf_file files[2] = {{-1, NULL, 0, ""}, {-1, NULL, 0, ""}};
int current_file_count = 0;

// פרוטוטיפים של פונקציות התפריט
void toggle_debug();
void examine_elf();
void print_sections();
void print_symbols();
void print_relocations();
void check_merge();
void merge_elf_files();
void not_implemented();
void quit();

struct fun_desc {
    char *name;
    void (*fun)();
};

// --- מימוש פונקציות העזר ---

void toggle_debug() {
    debug_mode = !debug_mode;
    printf("Debug mode is now %s\n", debug_mode ? "on" : "off");
}

void not_implemented() {
    printf("not implemented yet\n");
}

void quit() {
    if (debug_mode) fprintf(stderr, "Quitting...\n");
    for (int i = 0; i < 2; i++) {
        if (files[i].map_start != NULL) {
            munmap(files[i].map_start, files[i].file_size);
        }
        if (files[i].fd != -1) {
            close(files[i].fd);
        }
    }
    exit(0);
}

void examine_elf() {
    if (current_file_count >= 2) {
        printf("Error: Already handling 2 files.\n");
        return;
    }

    char filename[256];
    printf("Enter ELF file name: ");
    scanf("%s", filename);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("stat failed");
        close(fd);
        return;
    }

    void *map_ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_ptr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        return;
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *)map_ptr;

    if (header->e_ident[EI_MAG0] != ELFMAG0 || memcmp(&header->e_ident[EI_MAG1], "ELF", 3) != 0) {
        printf("Error: Not an ELF file.\n");
        munmap(map_ptr, st.st_size);
        close(fd);
        return;
    }

    files[current_file_count].fd = fd;
    files[current_file_count].map_start = map_ptr;
    files[current_file_count].file_size = st.st_size;
    strcpy(files[current_file_count].filename, filename);
    current_file_count++;

    // הדפסה לפי הדרישות המדויקות של המעבדה:
    printf("Magic: %c%c%c\n", header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    
    printf("Data encoding: ");
    if (header->e_ident[EI_DATA] == ELFDATA2LSB) printf("2's complement, little endian\n");
    else if (header->e_ident[EI_DATA] == ELFDATA2MSB) printf("2's complement, big endian\n");
    else printf("Unknown\n");

    printf("Entry point address: 0x%x\n", header->e_entry);
    printf("Start of section headers: %d (bytes into file)\n", header->e_shoff);
    printf("Number of section headers: %d\n", header->e_shnum);
    printf("Size of section headers: %d (bytes)\n", header->e_shentsize);
    printf("Start of program headers: %d (bytes into file)\n", header->e_phoff);
    printf("Number of program headers: %d\n", header->e_phnum);
    printf("Size of program headers: %d (bytes)\n", header->e_phentsize);
}
// --- ניהול התפריט ---

struct fun_desc menu[] = {
    {"Toggle Debug Mode", toggle_debug},
    {"Examine ELF File", examine_elf},
    {"Print Section Names", print_sections},
    {"Print Symbols", print_symbols},
    {"Print Relocations", print_relocations},
    {"Check Files for Merge", check_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit},
    {NULL, NULL}
};


void print_sections() {
    if (current_file_count == 0) {
        printf("Error: No ELF files have been opened. Use option 1 first.\n");
        return;
    }

    for (int i = 0; i < current_file_count; i++) {
        printf("File %s\n", files[i].filename);
        
        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        
        // מציאת ה-String Table של שמות ה-Sections
        Elf32_Shdr *shstrtab_hdr = &shdr_table[header->e_shstrndx];
        char *sh_strtab = (char *)(files[i].map_start + shstrtab_hdr->sh_offset);

        if (debug_mode) {
            fprintf(stderr, "Debug: shstrndx: %d, sh_offset: 0x%x\n", 
                    header->e_shstrndx, shstrtab_hdr->sh_offset);
        }

        // כותרת מיושרת היטב
        printf("[idx] %-18s %-10s %-10s %-10s %-10s\n", 
               "Name", "Address", "Offset", "Size", "Type");
        
        for (int j = 0; j < header->e_shnum; j++) {
            char *name = sh_strtab + shdr_table[j].sh_name;
            
            // הדפסה מיושרת עם ריפוד אפסים לכתובות והיסטים
            printf("[%2d] %-18s %08x   %08x   %08x   %d\n", 
                   j, 
                   name, 
                   shdr_table[j].sh_addr, 
                   shdr_table[j].sh_offset, 
                   shdr_table[j].sh_size, 
                   shdr_table[j].sh_type);
        }
        printf("\n");
    }
}

void print_symbols() {
    if (current_file_count == 0) {
        printf("Error: No ELF files examined. Use option 1 first.\n");
        return;
    }

    for (int i = 0; i < current_file_count; i++) {
        printf("File %s\n", files[i].filename);
        
        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        
        // טבלת שמות ה-Sections (בשביל להדפיס את section_name)
        char *sh_strtab = (char *)(files[i].map_start + shdr_table[header->e_shstrndx].sh_offset);

        int found_symtab = 0;
        for (int j = 0; j < header->e_shnum; j++) {
            if (shdr_table[j].sh_type == SHT_SYMTAB) {
                found_symtab = 1;
                Elf32_Shdr *symtab_hdr = &shdr_table[j];
                
                // מציאת טבלת המחרוזות של הסימבולים דרך שדה ה-sh_link
                char *strtab = (char *)(files[i].map_start + shdr_table[symtab_hdr->sh_link].sh_offset);
                
                int num_symbols = symtab_hdr->sh_size / sizeof(Elf32_Sym);
                Elf32_Sym *sym_table = (Elf32_Sym *)(files[i].map_start + symtab_hdr->sh_offset);

                if (debug_mode) {
                    fprintf(stderr, "Debug: Symbol table index: %d\n", j);
                    fprintf(stderr, "Debug: Symbol table size: %d bytes\n", symtab_hdr->sh_size);
                    fprintf(stderr, "Debug: Number of symbols found: %d\n", num_symbols);
                }

                // כותרת הטבלה
                printf("[idx] %-8s %-12s %-18s %-20s\n", "Value", "Sec_idx", "Section_Name", "Symbol_Name");

                for (int k = 0; k < num_symbols; k++) {
                    char *symbol_name = strtab + sym_table[k].st_name;
                    char section_name[32];
                    
                    // שליפת שם ה-Section בדיוק כמו קודם
                    if (sym_table[k].st_shndx == SHN_UNDEF) strcpy(section_name, "UND");
                    else if (sym_table[k].st_shndx == SHN_ABS) strcpy(section_name, "ABS");
                    else if (sym_table[k].st_shndx < header->e_shnum) {
                        strcpy(section_name, sh_strtab + shdr_table[sym_table[k].st_shndx].sh_name);
                    } else strcpy(section_name, "PRC");
                
                    // תיקון: אם השם ריק וזה סימבול של Section, נשתמש בשם ה-Section כשם הסימבול
                    char display_name[64];
                    if (sym_table[k].st_name == 0 && ELF32_ST_TYPE(sym_table[k].st_info) == STT_SECTION) {
                        strcpy(display_name, section_name);
                    } else {
                        strcpy(display_name, symbol_name);
                    }
                
                    printf("[%2d] %08x %-12d %-18s %-20s\n", 
                           k, sym_table[k].st_value, sym_table[k].st_shndx, section_name, display_name);
                }
            }
        }
        
        if (!found_symtab) {
            printf("Error: No symbol table found in this file.\n");
        }
        printf("\n");
    }
}

void print_relocations() {
    if (current_file_count == 0) {
        printf("Error: No ELF files examined yet.\n");
        return;
    }

    for (int i = 0; i < current_file_count; i++) {
        printf("File %s relocations\n", files[i].filename);
        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        int found_rel = 0;

        for (int j = 0; j < header->e_shnum; j++) {
            if (shdr_table[j].sh_type == SHT_REL) {
                found_rel = 1;
                Elf32_Rel *rel_table = (Elf32_Rel *)(files[i].map_start + shdr_table[j].sh_offset);
                int num_relocs = shdr_table[j].sh_size / sizeof(Elf32_Rel);

                Elf32_Shdr *symtab_hdr = &shdr_table[shdr_table[j].sh_link];
                Elf32_Sym *sym_table = (Elf32_Sym *)(files[i].map_start + symtab_hdr->sh_offset);
                char *strtab = (char *)(files[i].map_start + shdr_table[symtab_hdr->sh_link].sh_offset);

                if (debug_mode) {
                    fprintf(stderr, "Debug: Relocation section: %d, size: %d, symbols: %d\n", 
                            j, shdr_table[j].sh_size, symtab_hdr->sh_size / sizeof(Elf32_Sym));
                }

                // הפורמט המדויק שביקשת
                printf("[index] location  related_symbol_name  size  type\n");

                for (int k = 0; k < num_relocs; k++) {
                    int sym_idx = ELF32_R_SYM(rel_table[k].r_info);
                    int rel_type = ELF32_R_TYPE(rel_table[k].r_info);
                    
                    char *symbol_name = "";
                    if (sym_idx != 0) {
                        symbol_name = strtab + sym_table[sym_idx].st_name;
                    }

                    // ב-ELF32, ה-Relocations הנפוצים הם בגודל 4 בתים
                    int size = 4; 

                    printf("[%2d]    %08x  %-20s  %-4d  %d\n", 
                           k, 
                           rel_table[k].r_offset, 
                           symbol_name, 
                           size, 
                           rel_type);
                }
                printf("\n");
            }
        }

        if (!found_rel) {
            printf("No relocations found in this file.\n");
        }
    }
}

// פונקציית עזר לחיפוש סימבול לפי שם בטבלת סימבולים נתונה
Elf32_Sym* find_symbol(const char* name, Elf32_Sym* sym_table, int num_symbols, char* strtab) {
    for (int i = 1; i < num_symbols; i++) { // מדלגים על אינדקס 0
        if (strcmp(name, strtab + sym_table[i].st_name) == 0) {
            return &sym_table[i];
        }
    }
    return NULL;
}

void check_merge() {
    if (current_file_count != 2) {
        printf("Error: Exactly 2 ELF files must be opened for merge check.\n");
        return;
    }

    Elf32_Sym *symtabs[2];
    char *strtabs[2];
    int num_syms[2];

    // 1. הכנת נתונים עבור שני הקבצים
    for (int i = 0; i < 2; i++) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr = (Elf32_Shdr *)(files[i].map_start + ehdr->e_shoff);
        int symtab_count = 0;
        int symtab_idx = -1;

        for (int j = 0; j < ehdr->e_shnum; j++) {
            if (shdr[j].sh_type == SHT_SYMTAB) {
                symtab_count++;
                symtab_idx = j;
            }
        }

        if (symtab_count != 1) {
            printf("Feature not supported: File %s must have exactly one symbol table.\n", files[i].filename);
            return;
        }

        symtabs[i] = (Elf32_Sym *)(files[i].map_start + shdr[symtab_idx].sh_offset);
        num_syms[i] = shdr[symtab_idx].sh_size / sizeof(Elf32_Sym);
        strtabs[i] = (char *)(files[i].map_start + shdr[shdr[symtab_idx].sh_link].sh_offset);
    }

    // 2. לולאת בדיקה - מעבר על קובץ 1 מול קובץ 2 וגם להפך (כפי שנדרש)
    for (int current = 0; current < 2; current++) {
        int other = 1 - current;
        
        for (int i = 1; i < num_syms[current]; i++) {
            Elf32_Sym *sym1 = &symtabs[current][i];
            char *name1 = strtabs[current] + sym1->st_name;

            // מתעלמים מסימבולים ללא שם (כמו SECTION symbols שראינו קודם)
            if (strlen(name1) == 0) continue;

            Elf32_Sym *sym2 = find_symbol(name1, symtabs[other], num_syms[other], strtabs[other]);

            // בדיקת Multiply Defined (רק פעם אחת כדי לא להכפיל הודעות)
            if (current == 0 && sym2 != NULL) {
                if (sym1->st_shndx != SHN_UNDEF && sym2->st_shndx != SHN_UNDEF) {
                    printf("Symbol %s multiply defined\n", name1);
                }
            }

            // בדיקת Undefined
            if (sym1->st_shndx == SHN_UNDEF) {
                if (sym2 == NULL || sym2->st_shndx == SHN_UNDEF) {
                    printf("Symbol %s undefined\n", name1);
                }
            }
        }
    }
    
    printf("Check Merge completed.\n");
}

// פונקציית עזר למציאת Section לפי שם בקובץ נתון
Elf32_Shdr* find_section_by_name(void* map_start, const char* name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_start;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(map_start + ehdr->e_shoff);
    char *sh_strtab = (char *)(map_start + shdr[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(sh_strtab + shdr[i].sh_name, name) == 0) {
            return &shdr[i];
        }
    }
    return NULL;
}

void merge_elf_files() {
    if (current_file_count != 2) {
        printf("Error: Exactly 2 files must be open for merge.\n");
        return;
    }

    FILE *out = fopen("out.ro", "wb+");
    if (!out) {
        perror("Failed to create out.ro");
        return;
    }

    Elf32_Ehdr *h1 = (Elf32_Ehdr *)files[0].map_start;
    void *m1 = files[0].map_start;
    void *m2 = files[1].map_start;

    // 1. העתקת Header ראשוני מקובץ 1
    Elf32_Ehdr new_header = *h1;
    fwrite(&new_header, 1, sizeof(Elf32_Ehdr), out);

    // 2. הכנת טבלת Section Headers בזיכרון (עותק של קובץ 1)
    Elf32_Shdr *shdr1 = (Elf32_Shdr *)(m1 + h1->e_shoff);
    char *sh_strtab1 = (char *)(m1 + shdr1[h1->e_shstrndx].sh_offset);
    
    Elf32_Shdr *new_shdr_table = malloc(sizeof(Elf32_Shdr) * h1->e_shnum);
    memcpy(new_shdr_table, shdr1, sizeof(Elf32_Shdr) * h1->e_shnum);

    // 3. לולאה על ה-Sections: כתיבת תוכן ועדכון הטבלה החדשה
    for (int i = 0; i < h1->e_shnum; i++) {
        char *s_name = sh_strtab1 + shdr1[i].sh_name;
        
        // עדכון האופסט הנוכחי בקובץ הפלט
        new_shdr_table[i].sh_offset = ftell(out);

        if (strcmp(s_name, ".text") == 0 || strcmp(s_name, ".data") == 0 || strcmp(s_name, ".rodata") == 0) {
            // מיזוג: העתקה מקובץ 1
            fwrite(m1 + shdr1[i].sh_offset, 1, shdr1[i].sh_size, out);
            
            // מציאת אותו Section בקובץ 2 והצמדה שלו
            Elf32_Shdr *sh2 = find_section_by_name(m2, s_name);
            if (sh2) {
                fwrite(m2 + sh2->sh_offset, 1, sh2->sh_size, out);
                new_shdr_table[i].sh_size = shdr1[i].sh_size + sh2->sh_size;
            }
        } 
        else if (shdr1[i].sh_type != SHT_NULL && shdr1[i].sh_type != SHT_NOBITS) {
            // העתקה כפי שהיא עבור שאר ה-Sections (כמו .symtab, .strtab, .shstrtab)
            fwrite(m1 + shdr1[i].sh_offset, 1, shdr1[i].sh_size, out);
        }
    }

    // 4. כתיבת ה-Section Header Table לסוף הקובץ
    long shoff = ftell(out);
    fwrite(new_shdr_table, sizeof(Elf32_Shdr), h1->e_shnum, out);

    // 5. עדכון ה-Header הסופי עם האופסט של הטבלה
    new_header.e_shoff = shoff;
    fseek(out, 0, SEEK_SET);
    fwrite(&new_header, 1, sizeof(Elf32_Ehdr), out);

    free(new_shdr_table);
    fclose(out);
    printf("Merge completed: out.ro created successfully.\n");
}

int main(int argc, char **argv) {
    int choice;
    int menu_len = 0;
    while (menu[menu_len].name != NULL) menu_len++;

    while (1) {
        printf("\nChoose action:\n");
        for (int i = 0; i < menu_len; i++) {
            printf("%d-%s\n", i, menu[i].name);
        }
        printf("Option: ");
        if (scanf("%d", &choice) != 1) break;

        if (choice >= 0 && choice < menu_len) {
            menu[choice].fun();
        } else {
            printf("Invalid choice\n");
        }
    }
    return 0;
}

