import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from typing import Dict, List, Literal, Optional, Union
from urllib import request

BOLD = "\033[1m"


@dataclass(init=True, match_args=True, order=True, frozen=True, repr=True, eq=True)
class CVE:
    count_value: int
    title: Optional[str]
    ordinal: Optional[str]
    published: Optional[str]
    note_type: Optional[str]
    note_title: Optional[str]
    description: Optional[str]
    date_value: date

    def dict(
        self,
    ) -> Dict[
        Literal[
            "count_value",
            "title",
            "ordinal",
            "published",
            "note_type",
            "note_title",
            "description",
            "date_value",
        ],
        Union[int, str],
    ]:
        dict_value = asdict(self)
        dict_value["date_value"] = self.date_value.isoformat()
        return dict_value


# scans namespaces in CVRF
def scan_cvrf(tree: ET.ElementTree, prev_date: date):
    modified_cve_counts = 0
    published_csv_counts = 0
    cve_count = 0
    vuln_namespace: Dict[Literal["vuln"], str] = {
        "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1"
    }
    cve_list: List[CVE] = list()

    print("Starting scanning of cvrf.xml...")
    # Individually iterate through ALL the objects of type vulnerability
    for vulnerability in tree.findall("vuln:Vulnerability", vuln_namespace):
        title = vulnerability.find("vuln:Title", vuln_namespace).text
        ordinal = vulnerability.get("Ordinal", vuln_namespace)
        notes_element = vulnerability.findall("vuln:Notes", vuln_namespace)
        cve_count += len(notes_element)
        for notes in notes_element:

            # Check the current vulnerability's publish date
            for note in notes.findall(".//*[@Title='Published']"):
                published = note.text
                note_type = note.get("Type")
                note_title = note.get("Title")
                published_date = date.fromisoformat(published)
                # Vulnerability newly published?
                if published_date >= prev_date:
                    published_csv_counts += 1
                    description = vulnerability.find(".//*[@Type='Description']").text

                    cve_list.append(
                        CVE(
                            modified_cve_counts + published_csv_counts,
                            title,
                            ordinal,
                            published,
                            note_type,
                            note_title.lower(),
                            description,
                            date_value=published_date,
                        )
                    )

            # Check the current vulnerability's modification date
            for note in notes.findall(".//*[@Title='Modified']"):
                modified = note.text
                note_type = note.get("Type")
                note_title = note.get("Title")
                modified_date = date.fromisoformat(modified)
                # Vulnerability recently modified?
                if modified_date >= prev_date:
                    modified_cve_counts += 1
                    description = vulnerability.find(".//*[@Type='Description']").text

                    cve_list.append(
                        CVE(
                            modified_cve_counts + published_csv_counts,
                            title,
                            ordinal,
                            modified,
                            note_type,
                            note_title.lower(),
                            description,
                            date_value=modified_date,
                        )
                    )

    print("Finished scanning of cvrf.xml.", end="\n\n")

    print(BOLD.join("Description"), ":")
    print("-" * 50)
    print(f"{cve_count} total CVE entries found")
    print(f"{published_csv_counts} new CVEs were published since {prev_date}.")
    print(f"{modified_cve_counts} existing CVEs were modified since {prev_date}.")
    print("-" * 50)

    return (modified_cve_counts + published_csv_counts, cve_list)


def preety_print_download(block_num: int, read_size: int, total_size: int):
    total_downloaded = block_num * read_size / (1024 * 1024)
    total_mb = total_size / (1024 * 1024)
    bar = int(50 * total_downloaded / total_mb)
    sys.stdout.write("\r[%s%s]" % ("=" * bar + ">", " " * (50 - bar)))
    sys.stdout.flush()


if __name__ == "__main__":

    prev_date = date.today() - timedelta(days=1)

    # Downloads csrf_file from  https://cve.mitre.org/data/downloads/allitems-cvrf.xml
    cvrf_file = r"./cve_a.xml"
    outfile = f'./output_{date.today().isoformat().replace("-","_")}.json'
    # Details of cvrf are available at https://cve.mitre.org/cve/cvrf.html

    if not (os.path.exists(cvrf_file)):
        print("please wait ... downloading latest cvrf data....")
        response = request.urlretrieve(
            "https://cve.mitre.org/data/downloads/allitems-cvrf.xml",
            filename=cvrf_file,
            reporthook=preety_print_download,
        )
        print()

    print("Loading cvrf.xml...")
    startLoadTime = time.perf_counter()
    tree = ET.parse(cvrf_file)
    endLoadTime = time.perf_counter()
    print("Finished loading cvrf.xml.")
    total_count, cve_list = scan_cvrf(tree, prev_date)

    print("writing data in json file .... ")
    json.dump(
        {"cve": [cve.dict() for cve in cve_list], "total": total_count},
        open(outfile, "w"),
        indent=4,
    )
    print(f"completed -- filename: {outfile}")
