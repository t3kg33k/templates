import tkinter as tk
from tkinter import ttk, messagebox
import random

# ---------- Dice Logic ----------
def roll_die(sides, rolls):
    results = []
    for _ in range(rolls):
        results.append(random.randint(1, sides))
    return results

# ---------- GUI Logic ----------
def run_roll():
    try:
        sides = int(die_var.get())
        rolls = int(rolls_entry.get())

        if rolls <= 0:
            raise ValueError

        output.delete("1.0", tk.END)
        output.insert(tk.END, "Rolling, Good Luck!\n\n")

        results = roll_die(sides, rolls)
        for r in results:
            output.insert(tk.END, f"--- {r} ---\n")

    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number of rolls.")

# ---------- GUI Setup ----------
root = tk.Tk()
root.title("Dice Roller")
root.geometry("400x450")

# Die selection
die_var = tk.StringVar(value="20")

ttk.Label(root, text="Choose Die").pack(pady=5)
die_menu = ttk.Combobox(
    root,
    textvariable=die_var,
    values=["100", "20", "12", "10", "8", "6", "4"],
    state="readonly"
)
die_menu.pack()

# Rolls input
ttk.Label(root, text="Number of Rolls").pack(pady=5)
rolls_entry = ttk.Entry(root)
rolls_entry.pack()
rolls_entry.insert(0, "1")

# Roll button
ttk.Button(root, text="Roll Dice", command=run_roll).pack(pady=10)

# Output box
output = tk.Text(root, height=12, width=40)
output.pack(padx=10, pady=10)

# Exit button
ttk.Button(root, text="Exit", command=root.destroy).pack(pady=5)

root.mainloop()

