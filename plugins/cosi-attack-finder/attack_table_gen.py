"""
Author: Avinash Sudhodanan
Contact: firstname.lastname@imdea.org
Project: ElasTest, COSI
Description: This code can be used to generate
the attack tables for differentiating between two HTTP responses
"""
from pprint import pprint
import xlrd # Reading an excel file using Python


class COSIAttackTableGenerator:
    """
        COSIAttackTableGenerator Class
    """
    @staticmethod
    def strlist_to_list(strlist):
        """Converts a string representation of list to a list
        Args:
        strlist: string representation of the list
        Returns:
        The list representation of the input string
        """
        lst = []
        for event in strlist.lstrip('[').rstrip(']').split(','):
            lst.append(event.lstrip().rstrip().lstrip('\'').rstrip('\''))
        return lst

    @staticmethod
    def open_workbook(location):
        """Returns the 0th sheet of a .xslx workbook
        Args:
        location: the location of the .xslx workbook
        Returns:
        The pointer to the sheet of the .xslx workbook
        """
        workbook = xlrd.open_workbook(location)
        sheet = workbook.sheet_by_index(0)
        return sheet

    def generate_attack_tables(self):
        """Generates the attack table for each tag
        """
        attack_vectors=["events_fired"]
        efc_tags = ["script"]
        cosi_attacks = []
        for attack_vector in attack_vectors:
            if attack_vector == "events_fired":
                for efc_tag in efc_tags:
                    input_sheet = self.open_workbook("reports/"+efc_tag+"_tag_test_log.xlsx")
                    #output_sheet = self.open_workbook("reports/"+efc_tag+"_tag_attack_table.xlsx")

                    row_iter1=1
                    row_iter2=2
                    while(row_iter1<input_sheet.nrows):
                        row_iter2=row_iter1+1
                        while(row_iter2<input_sheet.nrows):
                            #print(row_iter1,row_iter2,input_sheet.nrows)
                            if(input_sheet.cell_value(row_iter1, 2)==input_sheet.cell_value(row_iter2, 2)):
                                #print(input_sheet.cell_value(row_iter1, 7),input_sheet.cell_value(row_iter2, 7))
                                if(input_sheet.cell_value(row_iter1, 7)!=input_sheet.cell_value(row_iter2, 7)):
                                    print("Differentiable states found:")
                                    print(input_sheet.cell_value(row_iter1, 3),input_sheet.cell_value(row_iter1, 5),input_sheet.cell_value(row_iter1, 6))
                                    print("and")
                                    print(input_sheet.cell_value(row_iter2, 3),input_sheet.cell_value(row_iter2, 5),input_sheet.cell_value(row_iter2, 6))
                            else:
                                break
                            row_iter2+=1
                        row_iter1+=1

if __name__ == "__main__":
    OBJECT_CATG = COSIAttackTableGenerator()
    OBJECT_CATG.generate_attack_tables()
