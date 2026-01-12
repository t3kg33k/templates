# Original script from https://github.com/peachpit-site/projects - 01/12/26
import random

def RollD100(rolls):
    for i in range(0, rolls):
        d100 = random.randint(1, 100)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d100)+ "---")
    print()
    Menu()

def RollD20(rolls):
    for i in range(0, rolls):
        d20 = random.randint(1, 20)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d20)+ "---")
    print()
    Menu()

def RollD12(rolls):
    for i in range(0, rolls):
        d12 = random.randint(1, 12)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d12)+ "---")
    print()
    Menu()

def RollD10(rolls):
    for i in range(0, rolls):
        d10 = random.randint(1, 10)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d10)+ "---")
    print()
    Menu()

def RollD8(rolls):
    for i in range(0, rolls):
        d8 = random.randint(1, 8)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d8)+ "---")
    print()
    Menu()
# Added d6 from original script
def RollD6(rolls):
    for i in range(0, rolls):
        d6 = random.randint(1, 6)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d6)+ "---")
    print()
    Menu()

def RollD4(rolls):
    for i in range(0, rolls):
        d4 = random.randint(1, 4)
        print("Rolling, Good Luck!")
        print()
        print("---" +str(d4)+ "---")
    print()
    Menu()


def Menu():
    print()
    print("-----------")
    print("1. d100")
    print("2. d20")
    print("3. d12")
    print("4. d10")
    print("5. d8")
    print("6. d6")
    print("7. d4")
    print("8. exit")
    print()
    choice = int(input("What Die Do You Need?: "))

    if(choice == 1):
        rolls = int(input("How many do you need to roll? "))
        RollD100(rolls)
    if(choice == 2):
        rolls = int(input("How many do you need to roll? "))
        RollD20(rolls)
    if(choice == 3):
        rolls = int(input("How many do you need to roll? "))
        RollD12(rolls)
    if(choice == 4):
        rolls = int(input("How many do you need to roll? "))
        RollD10(rolls)
    if(choice == 5):
        rolls = int(input("How many do you need to roll? "))
        RollD8(rolls)
    if(choice == 6):
        rolls = int(input("How many do you need to roll? "))
        RollD6(rolls)
    if(choice == 7):
        rolls = int(input("How many do you need to roll? "))
        RollD4(rolls)
    if(choice == 8):
        exit();

Menu()
