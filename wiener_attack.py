# -*- coding: utf-8 -*-

import ContinuedFractions
import Arithmetic


class WienerAttack(object):

    def __init__(self, e, n):
        '''
        Finds d knowing (e,n)
        applying the Wiener continued fraction attack
        '''
        self.d = None
        frac = ContinuedFractions.rational_to_contfrac(e, n)
        convergents = ContinuedFractions.convergents_from_contfrac(frac)
        for (k, d) in convergents:
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                discr = s*s - 4*n
                if(discr >= 0):
                    t = Arithmetic.is_perfect_square(discr)
                    if t != -1 and (s + t) % 2 == 0:
                        self.d = d


if __name__ == "__main__":
    e = 183660146490422285798428660546754134418661142835604115682836778081011910238113418914160492357183479746113831224890276245963351969616299252487295456989541604200510147067942532456361592226745633044460474515423373513962661902371609185806409826177631960057301188704604462752401029826856647332290955631046413984399
    n = 389515408296655148290581563863000908898325888640756426496565058741991532048866570395053437819242171431189565463308618089884040388226018251206386599176051383704265563914856452346660884236282775256432787225396880333641673220361268798095615195711784817151469713312677969226724758279474230622503252678286043442157
    wiener = WienerAttack(e, n)
    print wiener.d
