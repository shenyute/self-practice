/**
 * Definition for singly-linked list.
 * struct ListNode {
 *     int val;
 *     ListNode *next;
 *     ListNode(int x) : val(x), next(NULL) {}
 * };
 */
class Solution {
public:
    ListNode* addTwoNumbers(ListNode* l1, ListNode* l2) {
        int carry = 0;
        ListNode *previous = nullptr;
        ListNode *head = nullptr;
        while (l1 || l2) {
            int n1 = l1 ? l1->val : 0;
            int n2 = l2 ? l2->val : 0;
            int n = n1 + n2 + carry;
            carry = n / 10;
            ListNode* node = NewNode(n % 10);
            if (previous)
                previous->next = node;
            else
                head = node;
            previous = node;
            if (l1)
                l1 = l1->next;
            if (l2)
                l2 = l2->next;
        }
        if (carry) {
            ListNode* node = NewNode(carry);
            previous->next = node;
        }
        return head;
    }
private:
    ListNode* NewNode(int n) {
        return new ListNode(n);
    }
};
