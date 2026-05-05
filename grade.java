/**
 * This class is used to sort a collection of grades in ascending order
 * and return the average grade back to the user.
 *  * @version 0.1
 *  * @since 12-19-2022
 */

import java.util.Scanner;
public class Grades
{
    //I didn't write the Scanner in the main method as Grades.keyboard.next() since they're in the same class.
    public static Scanner keyboard=new Scanner(System.in);

    //Sorting the grades

    /**
     * Finds the smallest value in an array and returns its index.
     * @param firstIndex
     * @param array
     * @return
     */
    private static int getIndexOfSmallest (int firstIndex, double[] array)
    {
        double min= array[firstIndex];
        int indexOfSmallest= firstIndex;
        for (int index= firstIndex+1; index< array.length; index++)
        {
            if (array[index]< min)
            {
                min= array[index];
                indexOfSmallest= index;
            }
        }
        return indexOfSmallest;
    }

    /**
     * Swaps the value of two indices.
     * @param x
     * @param y
     * @param array
     */
    private static void swapIndices(int x, int y, double[] array)
    {
        double temp= array[x];
        array[x]=array[y];
        array[y]= temp;
    }

    /**
     * Swaps the index containing the smallest value with the value of the first index.
     * Repeats the process using the next smallest value and the index following the first
     * until the values of the index are sorted in ascending order.
     * @param array
     */
    private static void selectionSorting(double[] array)
    {
        for(int index=0; index<(array.length-1);index++)
        {
            int nextSmallest= getIndexOfSmallest(index, array);
            swapIndices(index, nextSmallest, array);
        }
    }

    /**
     * This method uses the selectionSorting method to order the grades in ascending order then prints them.
     * @param array
     */
    public static void sortGrades(double[] array)
    {
        selectionSorting(array);
        System.out.println("The grades in ascending order are as follows:");
        for(double grade: array)
        {
            System.out.println(grade);
        }
    }


    //Grade Calculations

    /**
     * This method prints the value of the first and last index of an array.
     * @param array
     */
    public static void findHighestAndLowestGrade(double[] array)
    {
        System.out.println("The highest grade is: "+(array[array.length-1]));
        System.out.println("The lowest grade is: "+array[0]);
    }


    /**
     * Finds the average of the values of an array.
     * @param array
     */
    public static void calculateAverage(double[] array)
    {
        double sumOfGrades= 0;
        double averageGrade;
        for (int index=0; index<(array.length); index++)
        {
            sumOfGrades= sumOfGrades+array[index];
        }
        averageGrade= sumOfGrades/(array.length);
        System.out.println("The average grade is "+averageGrade);
        if(averageGrade>=90)
        {
            System.out.println("Somebody's been studying.");
        }
        else if (averageGrade>=80)
        {
            System.out.println("Doing alright.");
        }
        else if (averageGrade>=70)
        {
            System.out.println("Could be better, but it could be worse.");
        }
        else if (averageGrade>=60)
        {
            System.out.println("Some could argue this is the bare minimum, but some improvement is highly recommended.");
        }
        else
        {
            System.out.println("This doesn't look great...");
        }
    }

    //Swapping a grade

    /**
     * This method searches for the index of the grade that will be changed.
     * Will notify user if input is invalid.
     * @param array
     * @return
     */
    private static int findIndex(double[] array)
    {
        System.out.println("Please enter the grade that you would like to change: ");
        double requestedGrade= keyboard.nextDouble();
        int targetIndex;
        int foundIndex=0;
        for (targetIndex=0;targetIndex<array.length; targetIndex++)
        {
            double targetGrade= array[targetIndex];
            if (targetGrade==requestedGrade)
            {
                foundIndex=targetIndex;
                break;
            }
            else if(targetIndex== array.length-1)
            {
                System.out.println("Grade not found.");
                System.out.println();
                System.out.println("Please enter the grade that you would like to change: ");
                requestedGrade= keyboard.nextDouble();
                targetIndex=0;
            }
        }
        return foundIndex;
    }

    /**
     * This method is used to replace grades in an array.
     * Reprints new set of grades in ascending order.
     * Reprints new highest and lowest grades.
     * Reprints new average grade.
     * @param array
     */
    public static void swapGrade(double[] array)
    {
        System.out.println("Would you like to change a grade?");
        System.out.println("Please enter yes or no: ");
        String response= keyboard.next();
        while (!(response.equalsIgnoreCase("yes")||response.equalsIgnoreCase("no")))
        {
            System.out.println("INVALID INPUT");
            System.out.println();
            System.out.println("Would you like to change a grade?");
            System.out.println("Please enter yes or no: ");
            response= keyboard.next();
        }
        if (response.equalsIgnoreCase("yes"))
        {
            int targetIndex=findIndex(array);

            //Making sure grade is valid
            do
            {
                System.out.println("Please enter new grade: ");
                array[targetIndex] = keyboard.nextDouble();
                if(array[targetIndex]<0)
                {
                    System.out.println("Cannot have a negative grade.");
                    System.out.println();
                }
                else if (array[targetIndex]>100)
                {
                    System.out.println("Grade cannot exceed 100.");
                    System.out.println();
                }
            }
            while((array[targetIndex]<0)||(array[targetIndex]>100));
            System.out.println();

            System.out.println("The grades have been updated");
            sortGrades(array);
            System.out.println();
            findHighestAndLowestGrade(array);
            calculateAverage(array);
            System.out.println();
            System.out.println("Thank you for using Evergrades. Have a nice day.");
            System.exit(0);

        }
        else
        {
            System.out.println("Thank you for using Evergrades. Have a nice day.");
            System.exit(0);
        }
    }


    //Running the program
    public static void main(String[] args)
    {

        System.out.println("Welcome to the Evergrades: The program for when you're swamped with grading.");
        System.out.println();

        //Inputting the quantity of grades
        int numOfGrades=0;
        while (numOfGrades <= 0)
        {
            System.out.println("Please enter the number of grades you'd like to input: ");
            numOfGrades= keyboard.nextInt();
            if(numOfGrades<0)
            {
                System.out.println("Cannot have a negative quantity of grades.");
                System.out.println();
            }
            else if (numOfGrades==0)
            {
                System.out.println("Cannot have no grades.");
                System.out.println();
            }

        }

        //Inputting the grades
        double[] grades= new double[numOfGrades];
        for(int i=0; i<numOfGrades; i++)
        {
            do
            {
                System.out.println("Please input grade #" + (i + 1) + ": ");
                grades[i] = keyboard.nextDouble();
                if(grades[i]<0)
                {
                    System.out.println("Cannot have a negative grade.");
                    System.out.println();
                }
                else if (grades[i]>100)
                {
                    System.out.println("Grade cannot exceed 100.");
                    System.out.println();
                }
            }
            while((grades[i]<0)||(grades[i]>100));
            System.out.println();
        }

        System.out.println();

        sortGrades(grades);
        System.out.println();
        findHighestAndLowestGrade(grades);
        calculateAverage(grades);
        System.out.println();
        swapGrade(grades);

        }
}
